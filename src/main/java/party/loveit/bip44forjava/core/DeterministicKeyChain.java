/*
 * Copyright by the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package party.loveit.bip44forjava.core;



import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import org.bouncycastle.crypto.params.KeyParameter;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import party.loveit.bip44forjava.crypto.DeterministicHierarchy;
import party.loveit.bip44forjava.crypto.DeterministicKey;
import party.loveit.bip44forjava.crypto.HDKeyDerivation;
import party.loveit.bip44forjava.crypto.HDUtils;
import party.loveit.bip44forjava.crypto.KeyCrypter;
import party.loveit.bip44forjava.crypto.KeyCrypterException;
import party.loveit.bip44forjava.listener.KeyChainEventListener;
import party.loveit.bip44forjava.utils.Threading;
import party.loveit.bip44forjava.utils.Utils;
import sun.font.Script;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A deterministic key chain is a {@link } that uses the
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP 32 standard</a>, as implemented by
 * {@link }, to derive all the keys in the keychain from a master seed.
 * This type of wallet is extremely convenient and flexible. Although backing up full wallet files is always a good
 * idea, to recover money only the root seed needs to be preserved and that is a number small enough that it can be
 * written down on paper or, when represented using a BIP 39 {@link },
 * dictated over the phone (possibly even memorized).</p>
 *
 * <p>Deterministic key chains have other advantages: parts of the key tree can be selectively revealed to allow
 * for auditing, and new public keys can be generated without access to the private keys, yielding a highly secure
 * configuration for web servers which can accept payments into a wallet but not spend from them. This does not work
 * quite how you would expect due to a quirk of elliptic curve mathematics and the techniques used to deal with it.
 * A watching wallet is not instantiated using the public part of the master key as you may imagine. Instead, you
 * need to take the account key (first child of the master key) and provide the public part of that to the watching
 * wallet instead. You can do this by calling {@link #getWatchingKey()} and then serializing it with
 * {@link #()}. The resulting "xpub..." string encodes
 * sufficient information about the account key to create a watching chain via
 * {@link #(, String, )}
 * (with null as the first parameter) and then
 * {@link DeterministicKeyChain#()}.</p>
 *
 * <p>This class builds on {@link } and
 * {@link } by adding support for serialization to and from protobufs,
 * and encryption of parts of the key tree. Internally it arranges itself as per the BIP 32 spec, with the seed being
 * used to derive a master key, which is then used to derive an account key, the account key is used to derive two
 * child keys called the <i>internal</i> and <i>external</i> parent keys (for change and handing out addresses respectively)
 * and finally the actual leaf keys that users use hanging off the end. The leaf keys are special in that they don't
 * internally store the private part at all, instead choosing to rederive the private key from the parent when
 * needed for signing. This simplifies the design for encrypted key chains.</p>
 *
 * <p>The key chain manages a <i>lookahead zone</i>. This zone is required because when scanning the chain, you don't
 * know exactly which keys might receive payments. The user may have handed out several addresses and received payments
 * on them, but for latency reasons the block chain is requested from remote peers in bulk, meaning you must
 * "look ahead" when calculating keys to put in the Bloom filter. The default lookahead zone is 100 keys, meaning if
 * the user hands out more than 100 addresses and receives payment on them before the chain is next scanned, some
 * transactions might be missed. 100 is a reasonable choice for consumer wallets running on CPU constrained devices.
 * For industrial wallets that are receiving keys all the time, a higher value is more appropriate. Ideally DKC and the
 * wallet would know how to adjust this value automatically, but that's not implemented at the moment.</p>
 *
 * <p>In fact the real size of the lookahead zone is larger than requested, by default, it's one third larger. This
 * is because the act of deriving new keys means recalculating the Bloom filters and this is an expensive operation.
 * Thus, to ensure we don't have to recalculate on every single new key/address requested or seen we add more buffer
 * space and only extend the lookahead zone when that buffer is exhausted. For example with a lookahead zone of 100
 * keys, you can request 33 keys before more keys will be calculated and the Bloom filter rebuilt and rebroadcast.
 * But even when you are requesting the 33rd key, you will still be looking 100 keys ahead.
 * </p>
 * 
 * @author Andreas Schildbach
 */
@SuppressWarnings("PublicStaticCollectionField")
public class DeterministicKeyChain implements EncryptableKeyChain {
    //private static final Logger log = LoggerFactory.getLogger(DeterministicKeyChain.class);
    public static final String DEFAULT_PASSPHRASE_FOR_MNEMONIC = "";

    protected final ReentrantLock lock = Threading.lock("DeterministicKeyChain");

    private DeterministicHierarchy hierarchy;
    @Nullable private DeterministicKey rootKey;
    @Nullable private DeterministicSeed seed;
    @Nullable private final ImmutableList<ChildNumber> accountPath;

    // Paths through the key tree. External keys are ones that are communicated to other parties. Internal keys are
    // keys created for change addresses, coinbases, mixing, etc - anything that isn't communicated. The distinction
    // is somewhat arbitrary but can be useful for audits. The first number is the "account number" but we don't use
    // that feature yet. In future we might hand out different accounts for cases where we wish to hand payers
    // a payment request that can generate lots of addresses independently.
    // The account path may be overridden by subclasses.
    public static final ImmutableList<ChildNumber> ACCOUNT_ZERO_PATH = ImmutableList.of(ChildNumber.ZERO_HARDENED);
    // m / 44' / 0' / 0'
    public static final ImmutableList<ChildNumber> BIP44_ACCOUNT_ZERO_PATH = ImmutableList.of(new ChildNumber(44, true),
            ChildNumber.ZERO_HARDENED, ChildNumber.ZERO_HARDENED);
    public static final ImmutableList<ChildNumber> EXTERNAL_SUBPATH = ImmutableList.of(ChildNumber.ZERO);
    public static final ImmutableList<ChildNumber> INTERNAL_SUBPATH = ImmutableList.of(ChildNumber.ONE);

    // We try to ensure we have at least this many keys ready and waiting to be handed out via getKey().
    // See docs for getLookaheadSize() for more info on what this is for. The -1 value means it hasn't been calculated
    // yet. For new chains it's set to whatever the default is, unless overridden by setLookaheadSize. For deserialized
    // chains, it will be calculated on demand from the number of loaded keys.
    private static final int LAZY_CALCULATE_LOOKAHEAD = -1;
    protected int lookaheadSize = 100;
    // The lookahead threshold causes us to batch up creation of new keys to minimize the frequency of Bloom filter
    // regenerations, which are expensive and will (in future) trigger chain download stalls/retries. One third
    // is an efficiency tradeoff.
    protected int lookaheadThreshold = calcDefaultLookaheadThreshold();

    private int calcDefaultLookaheadThreshold() {
        return lookaheadSize / 3;
    }

    // The parent keys for external keys (handed out to other people) and internal keys (used for change addresses).
    private DeterministicKey externalParentKey, internalParentKey;
    // How many keys on each path have actually been used. This may be fewer than the number that have been deserialized
    // or held in memory, because of the lookahead zone.
    private int issuedExternalKeys, issuedInternalKeys;
    // A counter that is incremented each time a key in the lookahead threshold zone is marked as used and lookahead
    // is triggered. The Wallet/KCG reads these counters and combines them so it can tell the Peer whether to throw
    // away the current block (and any future blocks in the same download batch) and restart chain sync once a new
    // filter has been calculated. This field isn't persisted to the wallet as it's only relevant within a network
    // session.
    private int keyLookaheadEpoch;

    // We simplify by wrapping a basic key chain and that way we get some functionality like key lookup and event
    // listeners "for free". All keys in the key tree appear here, even if they aren't meant to be used for receiving
    // money.
    //private final BasicKeyChain basicKeyChain;

    // If set this chain is following another chain in a married KeyChainGroup
    private boolean isFollowing;

    // holds a number of signatures required to spend. It's the N from N-of-M CHECKMULTISIG script for P2SH transactions
    // and always 1 for other transaction types
    protected int sigsRequiredToSpend = 1;


    public static class Builder<T extends Builder<T>> {
        protected SecureRandom random;
        protected int bits = 128;
        protected String passphrase;
        protected long seedCreationTimeSecs;
        protected byte[] entropy;
        protected DeterministicSeed seed;
        protected DeterministicKey watchingKey;

        protected Builder() {
        }

        @SuppressWarnings("unchecked")
        protected T self() {
            return (T)this;
        }

        /**
         * Creates a deterministic key chain starting from the given entropy. All keys yielded by this chain will be the same
         * if the starting entropy is the same. You should provide the creation time in seconds since the UNIX epoch for the
         * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
         */
        public T entropy(byte[] entropy) {
            this.entropy = entropy;
            return self();
        }

        /**
         * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
         * if the starting seed is the same.
         */
        public T seed(DeterministicSeed seed) {
            this.seed = seed;
            return self();
        }

        /**
         * Generates a new key chain with entropy selected randomly from the given {@link SecureRandom}
         * object and of the requested size in bits.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         * @param bits The number of bits of entropy to use when generating entropy.  Either 128 (default), 192 or 256.
         */
        public T random(SecureRandom random, int bits) {
            this.random = random;
            this.bits = bits;
            return self();
        }

        /**
         * Generates a new key chain with 128 bits of entropy selected randomly from the given {@link SecureRandom}
         * object.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         */
        public T random(SecureRandom random) {
            this.random = random;
            return self();
        }

        public T watchingKey(DeterministicKey watchingKey) {
            this.watchingKey = watchingKey;
            return self();
        }

        public T seedCreationTimeSecs(long seedCreationTimeSecs) {
            this.seedCreationTimeSecs = seedCreationTimeSecs;
            return self();
        }

        /** The passphrase to use with the generated mnemonic, or null if you would like to use the default empty string. Currently must be the empty string. */
        public T passphrase(String passphrase) {
            // FIXME support non-empty passphrase
            this.passphrase = passphrase;
            return self();
        }

        public DeterministicKeyChain build() {
            checkState(random != null || entropy != null || seed != null || watchingKey!= null, "Must provide either entropy or random or seed or watchingKey");
            checkState(passphrase == null || seed == null, "Passphrase must not be specified with seed");
            DeterministicKeyChain chain;

            if (random != null) {
                // Default passphrase to "" if not specified
                chain = new DeterministicKeyChain(random, bits, getPassphrase(), seedCreationTimeSecs);
            } else if (entropy != null) {
                chain = new DeterministicKeyChain(entropy, getPassphrase(), seedCreationTimeSecs);
            } else if (seed != null) {
                seed.setCreationTimeSeconds(seedCreationTimeSecs);
                chain = new DeterministicKeyChain(seed);
            } else {
                watchingKey.setCreationTimeSeconds(seedCreationTimeSecs);
                chain = new DeterministicKeyChain(watchingKey);
            }

            return chain;
        }

        protected String getPassphrase() {
            return passphrase != null ? passphrase : DEFAULT_PASSPHRASE_FOR_MNEMONIC;
        }
    }

    public static Builder<?> builder() {
        return new Builder();
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link SecureRandom}
     * object and the default entropy size.
     */
    public DeterministicKeyChain(SecureRandom random) {
        this(random, DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS, DEFAULT_PASSPHRASE_FOR_MNEMONIC, Utils.currentTimeSeconds());
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link SecureRandom}
     * object and of the requested size in bits.
     */
    public DeterministicKeyChain(SecureRandom random, int bits) {
        this(random, bits, DEFAULT_PASSPHRASE_FOR_MNEMONIC, Utils.currentTimeSeconds());
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link SecureRandom}
     * object and of the requested size in bits.  The derived seed is further protected with a user selected passphrase
     * (see BIP 39).
     */
    public DeterministicKeyChain(SecureRandom random, int bits, String passphrase, long seedCreationTimeSecs) {
        this(new DeterministicSeed(random, bits, passphrase, seedCreationTimeSecs));
    }

    /**
     * Creates a deterministic key chain starting from the given entropy. All keys yielded by this chain will be the same
     * if the starting seed is the same. You should provide the creation time in seconds since the UNIX epoch for the
     * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
     */
    public DeterministicKeyChain(byte[] entropy, String passphrase, long seedCreationTimeSecs) {
        this(new DeterministicSeed(entropy, passphrase, seedCreationTimeSecs));
    }

    /**
     * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
     * if the starting seed is the same.
     */
    protected DeterministicKeyChain(DeterministicSeed seed) {
        this(seed, null, ACCOUNT_ZERO_PATH);
    }

    /**
     * Creates a deterministic key chain starting from the given seed. This deterministic Key chain
     * will follow the account path defined.
     */
    public DeterministicKeyChain(DeterministicSeed seed, ImmutableList<ChildNumber> accountPath) {
        this(seed, null, accountPath);
    }

    /**
     * Creates a deterministic key chain that watches the given (public only) root key. You can use this to calculate
     * balances and generally follow along, but spending is not possible with such a chain.
     */
    public DeterministicKeyChain(DeterministicKey watchingKey) {
        checkArgument(watchingKey.isPubKeyOnly(), "Private subtrees not currently supported: if you got this key from DKC.getWatchingKey() then use .dropPrivate().dropParent() on it first.");
        this.accountPath = watchingKey.getPath();
       // basicKeyChain = new BasicKeyChain();
        this.seed = null;
        this.rootKey = null;
//       / basicKeyChain.importKey(watchingKey);
        hierarchy = new DeterministicHierarchy(watchingKey);
    }

    /**
     * Creates a deterministic key chain from a watched or spendable account key.  If  {@code isWatching} flag is set,
     * then creates a deterministic key chain that watches the given (public only) root key.  You can use this to calculate
     * balances and generally follow along, but spending is not possible with such a chain.  If it is not set, then this
     * creates a deterministic key chain that allows spending. If {@code isFollowing} flag is set(only allowed
     * if {@code isWatching} is set) then this keychain follows some other keychain.  In a married wallet following
     * keychain represents "spouse's" keychain.
     */
    public DeterministicKeyChain(DeterministicKey key, boolean isFollowing, boolean isWatching) {
        if (isWatching)
            checkArgument(key.isPubKeyOnly(), "Private subtrees not currently supported for watching keys: if you got this key from DKC.getWatchingKey() then use .dropPrivate().dropParent() on it first.");
        else
            checkArgument(key.hasPrivKey(), "Private subtrees are required.");
        checkArgument(isWatching || !isFollowing, "Can only follow a key that is watched");

       // basicKeyChain = new BasicKeyChain();
        this.seed = null;
        this.rootKey = null;
        //basicKeyChain.importKey(key);
        hierarchy = new DeterministicHierarchy(key);
        this.accountPath = key.getPath();
        this.isFollowing = isFollowing;
    }

    /**
     * <p>Creates a deterministic key chain with the given watch key. If {@code isFollowing} flag is set then this keychain follows
     * some other keychain. In a married wallet following keychain represents "spouse's" keychain.</p>
     * <p>Watch key has to be an account key.</p>
     */
    protected DeterministicKeyChain(DeterministicKey watchKey, boolean isFollowing) {
        this(watchKey);
        this.isFollowing = isFollowing;
    }

    /**
     * Creates a deterministic key chain with the given watch key and that follows some other keychain. In a married
     * wallet following keychain represents "spouse"
     * Watch key has to be an account key.
     */
    public static DeterministicKeyChain watchAndFollow(DeterministicKey watchKey) {
        return new DeterministicKeyChain(watchKey, true);
    }

    /**
     * Creates a key chain that watches the given account key.
     */
    public static DeterministicKeyChain watch(DeterministicKey accountKey) {
        return new DeterministicKeyChain(accountKey);
    }

    /**
     * Creates a key chain that can spend from the given account key.
     */
    public static DeterministicKeyChain spend(DeterministicKey accountKey) {
        return new DeterministicKeyChain(accountKey, false, false);
    }

    /**
     * For use in {@link } during deserialization.
     */
    protected DeterministicKeyChain(DeterministicSeed seed, @Nullable KeyCrypter crypter) {
        this(seed, crypter, ACCOUNT_ZERO_PATH);
    }

    /**
     * Creates a deterministic key chain with an encrypted deterministic seed using the provided account path.
     *  Using {@link  KeyCrypter} to decrypt.
     */
    protected DeterministicKeyChain(DeterministicSeed seed, @Nullable KeyCrypter crypter,
                                    ImmutableList<ChildNumber> accountPath) {
        this.accountPath = accountPath;
        this.seed = seed;
        if (!seed.isEncrypted()) {
            rootKey = HDKeyDerivation.createMasterPrivateKey(checkNotNull(seed.getSeedBytes()));
            rootKey.setCreationTimeSeconds(seed.getCreationTimeSeconds());
            hierarchy = new DeterministicHierarchy(rootKey);
        }
    }


    /** Override in subclasses to use a different account derivation path */
    protected ImmutableList<ChildNumber> getAccountPath() {
        if (accountPath != null)
            return accountPath;
        return ACCOUNT_ZERO_PATH;
    }



    /** Returns a freshly derived key that has not been returned by this method before. */
    @Override
    public DeterministicKey getKey(KeyPurpose purpose) {
        return getKeys(purpose, 1).get(0);
    }

    /** Returns freshly derived key/s that have not been returned by this method before. */
    @Override
    public List<DeterministicKey> getKeys(KeyPurpose purpose, int numberOfKeys) {
        checkArgument(numberOfKeys > 0);
        lock.lock();
        try {
            DeterministicKey parentKey;
            int index;
            switch (purpose) {
                // Map both REFUND and RECEIVE_KEYS to the same branch for now. Refunds are a feature of the BIP 70
                // payment protocol. Later we may wish to map it to a different branch (in a new wallet version?).
                // This would allow a watching wallet to only be able to see inbound payments, but not change
                // (i.e. spends) or refunds. Might be useful for auditing ...
                case RECEIVE_FUNDS:
                case REFUND:
                    issuedExternalKeys += numberOfKeys;
                    index = issuedExternalKeys;
                    parentKey = externalParentKey;
                    break;
                case AUTHENTICATION:
                case CHANGE:
                    issuedInternalKeys += numberOfKeys;
                    index = issuedInternalKeys;
                    parentKey = internalParentKey;
                    break;
                default:
                    throw new UnsupportedOperationException();
            }
            // Optimization: potentially do a very quick key generation for just the number of keys we need if we
            // didn't already create them, ignoring the configured lookahead size. This ensures we'll be able to
            // retrieve the keys in the following loop, but if we're totally fresh and didn't get a chance to
            // calculate the lookahead keys yet, this will not block waiting to calculate 100+ EC point multiplies.
            // On slow/crappy Android phones looking ahead 100 keys can take ~5 seconds but the OS will kill us
            // if we block for just one second on the UI thread. Because UI threads may need an address in order
            // to render the screen, we need getKeys to be fast even if the wallet is totally brand new and lookahead
            // didn't happen yet.
            //
            // It's safe to do this because when a network thread tries to calculate a Bloom filter, we'll go ahead
            // and calculate the full lookahead zone there, so network requests will always use the right amount.
            List<DeterministicKey> lookahead = maybeLookAhead(parentKey, index, 0, 0);
            //basicKeyChain.importKeys(lookahead);
            List<DeterministicKey> keys = new ArrayList<>(numberOfKeys);
            for (int i = 0; i < numberOfKeys; i++) {
                ImmutableList<ChildNumber> path = HDUtils.append(parentKey.getPath(), new ChildNumber(index - numberOfKeys + i, false));
                DeterministicKey k = hierarchy.get(path, false, false);
                // Just a last minute sanity check before we hand the key out to the app for usage. This isn't inspired
                // by any real problem reports from bitcoinj users, but I've heard of cases via the grapevine of
                // places that lost money due to bitflips causing addresses to not match keys. Of course in an
                // environment with flaky RAM there's no real way to always win: bitflips could be introduced at any
                // other layer. But as we're potentially retrieving from long term storage here, check anyway.
                checkForBitFlip(k);
                keys.add(k);
            }
            return keys;
        } finally {
            lock.unlock();
        }
    }

    private void checkForBitFlip(DeterministicKey k) {
        DeterministicKey parent = checkNotNull(k.getParent());
        byte[] rederived = HDKeyDerivation.deriveChildKeyBytesFromPublic(parent, k.getChildNumber(), HDKeyDerivation.PublicDeriveMode.WITH_INVERSION).keyBytes;
        byte[] actual = k.getPubKey();
        if (!Arrays.equals(rederived, actual))
            throw new IllegalStateException(String.format(Locale.US, "Bit-flip check failed: %s vs %s", Arrays.toString(rederived), Arrays.toString(actual)));
    }

    /**
     * Mark the DeterministicKey as used.
     * Also correct the issued{Internal|External}Keys counter, because all lower children seem to be requested already.
     * If the counter was updated, we also might trigger lookahead.
     */
    public DeterministicKey markKeyAsUsed(DeterministicKey k) {
        int numChildren = k.getChildNumber().i() + 1;

        if (k.getParent() == internalParentKey) {
            if (issuedInternalKeys < numChildren) {
                issuedInternalKeys = numChildren;
                maybeLookAhead();
            }
        } else if (k.getParent() == externalParentKey) {
            if (issuedExternalKeys < numChildren) {
                issuedExternalKeys = numChildren;
                maybeLookAhead();
            }
        }
        return k;
    }

    /*public DeterministicKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubHash(pubkeyHash);
        } finally {
            lock.unlock();
        }
    }

    public DeterministicKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubKey(pubkey);
        } finally {
            lock.unlock();
        }
    }*/

    /**
     * Mark the DeterministicKeys as used, if they match the pubkeyHash
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
   /* @Nullable
    public DeterministicKey markPubHashAsUsed(byte[] pubkeyHash) {
        lock.lock();
        try {
            DeterministicKey k = (DeterministicKey) basicKeyChain.findKeyFromPubHash(pubkeyHash);
            if (k != null)
                markKeyAsUsed(k);
            return k;
        } finally {
            lock.unlock();
        }
    }*/

    /**
     * Mark the DeterministicKeys as used, if they match the pubkey
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
  /*  @Nullable
    public DeterministicKey markPubKeyAsUsed(byte[] pubkey) {
        lock.lock();
        try {
            DeterministicKey k = (DeterministicKey) basicKeyChain.findKeyFromPubKey(pubkey);
            if (k != null)
                markKeyAsUsed(k);
            return k;
        } finally {
            lock.unlock();
        }
    }*/

   /* @Override
    public boolean hasKey(ECKey key) {
        lock.lock();
        try {
            return basicKeyChain.hasKey(key);
        } finally {
            lock.unlock();
        }
    }*/

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    protected DeterministicKey getKeyByPath(ChildNumber... path) {
        return getKeyByPath(ImmutableList.copyOf(path));
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    protected DeterministicKey getKeyByPath(List<ChildNumber> path) {
        return getKeyByPath(path, false);
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy, optionally creating it */
    public DeterministicKey getKeyByPath(List<ChildNumber> path, boolean create) {
        return hierarchy.get(path, false, create);
    }

    /**
     * <p>An alias for {@code getKeyByPath(getAccountPath())}.</p>
     *
     * <p>Use this when you would like to create a watching key chain that follows this one, but can't spend money from it.
     * The returned key can be serialized and then passed into {@link #watch(DeterministicKey)}
     * on another system to watch the hierarchy.</p>
     *
     * <p>Note that the returned key is not pubkey only unless this key chain already is: the returned key can still
     * be used for signing etc if the private key bytes are available.</p>
     */
    public DeterministicKey getWatchingKey() {
        return getKeyByPath(getAccountPath());
    }

    /** Returns true if this chain is watch only, meaning it has public keys but no private key. */
    public boolean isWatching() {
        return getWatchingKey().isWatching();
    }

    @Override
    public int numKeys() {
        // We need to return here the total number of keys including the lookahead zone, not the number of keys we
        // have issued via getKey/freshReceiveKey.
        /*lock.lock();
        try {
            maybeLookAhead();
            return basicKeyChain.numKeys();
        } finally {
            lock.unlock();
        }*/

        return 0;
    }

    /**
     * Returns number of leaf keys used including both internal and external paths. This may be fewer than the number
     * that have been deserialized or held in memory, because of the lookahead zone.
     */
    public int numLeafKeysIssued() {
        lock.lock();
        try {
            return issuedExternalKeys + issuedInternalKeys;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long getEarliestKeyCreationTime() {
        if (seed != null)
            return seed.getCreationTimeSeconds();
        else
            return getWatchingKey().getCreationTimeSeconds();
    }

    @Override
    public void addEventListener(KeyChainEventListener listener) {
       // basicKeyChain.addEventListener(listener);
    }

    @Override
    public void addEventListener(KeyChainEventListener listener, Executor executor) {
        //basicKeyChain.addEventListener(listener, executor);
    }

    @Override
    public boolean removeEventListener(KeyChainEventListener listener) {
        //return basicKeyChain.removeEventListener(listener);
        return true;
    }

    /** Returns a list of words that represent the seed or null if this chain is a watching chain. */
    @Nullable
    public List<String> getMnemonicCode() {
        if (seed == null) return null;

        lock.lock();
        try {
            return seed.getMnemonicCode();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Return true if this keychain is following another keychain
     */
    public boolean isFollowing() {
        return isFollowing;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Serialization support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    @Override
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result = newArrayList();
        lock.lock();
        try {
            result.addAll(serializeMyselfToProtobuf());
        } finally {
            lock.unlock();
        }
        return result;
    }*/


    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Encryption support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

   /* @Override
    public DeterministicKeyChain toEncrypted(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        checkState(seed != null, "Attempt to encrypt a watching chain.");
        checkState(!seed.isEncrypted());
        KeyCrypter scrypt = new KeyCrypterScrypt();
        KeyParameter derivedKey = scrypt.deriveKey(password);
        return toEncrypted(scrypt, derivedKey);
    }*/

   /* @Override
    public DeterministicKeyChain toEncrypted(KeyCrypter keyCrypter, KeyParameter aesKey) {
        return new DeterministicKeyChain(keyCrypter, aesKey, this);
    }
*/
   /* @Override
    public DeterministicKeyChain toDecrypted(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        KeyCrypter crypter = getKeyCrypter();
        checkState(crypter != null, "Chain not encrypted");
        KeyParameter derivedKey = crypter.deriveKey(password);
        return toDecrypted(derivedKey);
    }*/

   /* @Override
    public DeterministicKeyChain toDecrypted(KeyParameter aesKey) {
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        checkState(seed != null, "Can't decrypt a watching chain");
        checkState(seed.isEncrypted());
        String passphrase = DEFAULT_PASSPHRASE_FOR_MNEMONIC; // FIXME allow non-empty passphrase
        DeterministicSeed decSeed = seed.decrypt(getKeyCrypter(), passphrase, aesKey);
        DeterministicKeyChain chain = makeKeyChainFromSeed(decSeed, getAccountPath());
        // Now double check that the keys match to catch the case where the key is wrong but padding didn't catch it.
        if (!chain.getWatchingKey().getPubKeyPoint().equals(getWatchingKey().getPubKeyPoint()))
            throw new KeyCrypterException("Provided AES key is wrong");
        chain.lookaheadSize = lookaheadSize;
        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to decrypt.
        for (ECKey eckey : basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != getAccountPath().size() + 2) continue; // Not a leaf key.
            checkState(key.isEncrypted());
            DeterministicKey parent = chain.hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new decrypted hierarchy.
            key = new DeterministicKey(key.dropPrivateBytes(), parent);
            chain.hierarchy.putKey(key);
            chain.basicKeyChain.importKey(key);
        }
        chain.issuedExternalKeys = issuedExternalKeys;
        chain.issuedInternalKeys = issuedInternalKeys;
        return chain;
    }*/

    /**
     * Factory method to create a key chain from a seed.
     * Subclasses should override this to create an instance of the subclass instead of a plain DKC.
     * This is used in encryption/decryption.
     */
    protected DeterministicKeyChain makeKeyChainFromSeed(DeterministicSeed seed, ImmutableList<ChildNumber> accountPath) {
        return new DeterministicKeyChain(seed, accountPath);
    }

    @Override
    public EncryptableKeyChain toEncrypted(CharSequence password) {
        return null;
    }

    @Override
    public EncryptableKeyChain toEncrypted(KeyCrypter keyCrypter, KeyParameter aesKey) {
        return null;
    }

    @Override
    public EncryptableKeyChain toDecrypted(CharSequence password) {
        return null;
    }

    @Override
    public EncryptableKeyChain toDecrypted(KeyParameter aesKey) {
        return null;
    }

    @Override
    public boolean checkPassword(CharSequence password) {
        checkNotNull(password);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        return checkAESKey(getKeyCrypter().deriveKey(password));
    }

    @Override
    public boolean checkAESKey(KeyParameter aesKey) {
        checkState(rootKey != null, "Can't check password for a watching chain");
        checkNotNull(aesKey);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        try {
            return rootKey.decrypt(aesKey).getPubKeyPoint().equals(rootKey.getPubKeyPoint());
        } catch (KeyCrypterException e) {
            return false;
        }
    }

    @Nullable
    @Override
    public KeyCrypter getKeyCrypter() {
        return null;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Bloom filtering support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /*@Override
    public int numBloomFilterEntries() {
        return numKeys() * 2;
    }*/

   /* @Override
    public BloomFilter getFilter(int size, double falsePositiveRate, long tweak) {
        lock.lock();
        try {
            checkArgument(size >= numBloomFilterEntries());
            maybeLookAhead();
            return basicKeyChain.getFilter(size, falsePositiveRate, tweak);
        } finally {
            lock.unlock();
        }

    }*/

    /**
     * <p>The number of public keys we should pre-generate on each path before they are requested by the app. This is
     * required so that when scanning through the chain given only a seed, we can give enough keys to the remote node
     * via the Bloom filter such that we see transactions that are "from the future", for example transactions created
     * by a different app that's sharing the same seed, or transactions we made before but we're replaying the chain
     * given just the seed. The default is 100.</p>
     */
    public int getLookaheadSize() {
        lock.lock();
        try {
            return lookaheadSize;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets a new lookahead size. See {@link #getLookaheadSize()} for details on what this is. Setting a new size
     * that's larger than the current size will return immediately and the new size will only take effect next time
     * a fresh filter is requested (e.g. due to a new peer being connected). So you should set this before starting
     * to sync the chain, if you want to modify it. If you haven't modified the lookahead threshold manually then
     * it will be automatically set to be a third of the new size.
     */
    public void setLookaheadSize(int lookaheadSize) {
        lock.lock();
        try {
            boolean readjustThreshold = this.lookaheadThreshold == calcDefaultLookaheadThreshold();
            this.lookaheadSize = lookaheadSize;
            if (readjustThreshold)
                this.lookaheadThreshold = calcDefaultLookaheadThreshold();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the threshold for the key pre-generation. This is used to avoid adding new keys and thus
     * re-calculating Bloom filters every time a new key is calculated. Without a lookahead threshold, every time we
     * received a relevant transaction we'd extend the lookahead zone and generate a new filter, which is inefficient.
     */
    public void setLookaheadThreshold(int num) {
        lock.lock();
        try {
            if (num >= lookaheadSize)
                throw new IllegalArgumentException("Threshold larger or equal to the lookaheadSize");
            this.lookaheadThreshold = num;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Gets the threshold for the key pre-generation. See {@link #setLookaheadThreshold(int)} for details on what this
     * is. The default is a third of the lookahead size (100 / 3 == 33). If you don't modify it explicitly then this
     * value will always be one third of the lookahead size.
     */
    public int getLookaheadThreshold() {
        lock.lock();
        try {
            if (lookaheadThreshold >= lookaheadSize)
                return 0;
            return lookaheadThreshold;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Pre-generate enough keys to reach the lookahead size. You can call this if you need to explicitly invoke
     * the lookahead procedure, but it's normally unnecessary as it will be done automatically when needed.
     */
    public void maybeLookAhead() {
        lock.lock();
        try {
            List<DeterministicKey> keys = maybeLookAhead(externalParentKey, issuedExternalKeys);
            keys.addAll(maybeLookAhead(internalParentKey, issuedInternalKeys));
            if (keys.isEmpty())
                return;
            keyLookaheadEpoch++;
            // Batch add all keys at once so there's only one event listener invocation, as this will be listened to
            // by the wallet and used to rebuild/broadcast the Bloom filter. That's expensive so we don't want to do
            // it more often than necessary.
            //basicKeyChain.importKeys(keys);
        } finally {
            lock.unlock();
        }
    }

    private List<DeterministicKey> maybeLookAhead(DeterministicKey parent, int issued) {
        checkState(lock.isHeldByCurrentThread());
        return maybeLookAhead(parent, issued, getLookaheadSize(), getLookaheadThreshold());
    }

    /**
     * Pre-generate enough keys to reach the lookahead size, but only if there are more than the lookaheadThreshold to
     * be generated, so that the Bloom filter does not have to be regenerated that often.
     *
     * The returned mutable list of keys must be inserted into the basic key chain.
     */
    private List<DeterministicKey> maybeLookAhead(DeterministicKey parent, int issued, int lookaheadSize, int lookaheadThreshold) {
        checkState(lock.isHeldByCurrentThread());
        final int numChildren = hierarchy.getNumChildren(parent.getPath());
        final int needed = issued + lookaheadSize + lookaheadThreshold - numChildren;

        if (needed <= lookaheadThreshold)
            return new ArrayList<>();


        List<DeterministicKey> result  = new ArrayList<>(needed);
        final Stopwatch watch = Stopwatch.createStarted();
        int nextChild = numChildren;
        for (int i = 0; i < needed; i++) {
            DeterministicKey key = HDKeyDerivation.deriveThisOrNextChildKey(parent, nextChild);
            key = key.dropPrivateBytes();
            hierarchy.putKey(key);
            result.add(key);
            nextChild = key.getChildNumber().num() + 1;
        }
        watch.stop();
        return result;
    }

    /** Housekeeping call to call when lookahead might be needed.  Normally called automatically by KeychainGroup. */
    public void maybeLookAheadScripts() {
    }

    /**
     * Returns number of keys used on external path. This may be fewer than the number that have been deserialized
     * or held in memory, because of the lookahead zone.
     */
    public int getIssuedExternalKeys() {
        lock.lock();
        try {
            return issuedExternalKeys;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns number of keys used on internal path. This may be fewer than the number that have been deserialized
     * or held in memory, because of the lookahead zone.
     */
    public int getIssuedInternalKeys() {
        lock.lock();
        try {
            return issuedInternalKeys;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the seed or null if this chain is a watching chain. */
    @Nullable
    public DeterministicSeed getSeed() {
        lock.lock();
        try {
            return seed;
        } finally {
            lock.unlock();
        }
    }

    // For internal usage only
    /* package */
   /* List<ECKey> getKeys(boolean includeLookahead, boolean includeParents) {
        List<ECKey> keys = basicKeyChain.getKeys();
        if (!includeLookahead) {
            int treeSize = internalParentKey.getPath().size();
            List<ECKey> issuedKeys = new LinkedList<>();
            for (ECKey key : keys) {
                DeterministicKey detkey = (DeterministicKey) key;
                DeterministicKey parent = detkey.getParent();
                if (!includeParents && parent == null) continue;
                if (!includeParents && detkey.getPath().size() <= treeSize) continue;
                if (internalParentKey.equals(parent) && detkey.getChildNumber().i() >= issuedInternalKeys) continue;
                if (externalParentKey.equals(parent) && detkey.getChildNumber().i() >= issuedExternalKeys) continue;
                issuedKeys.add(detkey);
            }
            return issuedKeys;
        }
        return keys;
    }*/

    /**
     * Returns only the external keys that have been issued by this chain, lookahead not included.
     */
   /* public List<ECKey> getIssuedReceiveKeys() {
        final List<ECKey> keys = new ArrayList<>(getKeys(false, false));
        for (Iterator<ECKey> i = keys.iterator(); i.hasNext();) {
            DeterministicKey parent = ((DeterministicKey) i.next()).getParent();
            if (parent == null || !externalParentKey.equals(parent))
                i.remove();
        }
        return keys;
    }*/

    /**
     * Returns leaf keys issued by this chain (including lookahead zone)
     */
   /* public List<DeterministicKey> getLeafKeys() {
        ImmutableList.Builder<DeterministicKey> keys = ImmutableList.builder();
        for (ECKey key : getKeys(true, false)) {
            DeterministicKey dKey = (DeterministicKey) key;
            if (dKey.getPath().size() == getAccountPath().size() + 2) {
                keys.add(dKey);
            }
        }
        return keys.build();
    }*/



    /**
     * Returns a counter that is incremented each time new keys are generated due to lookahead. Used by the network
     * code to learn whether to discard the current block and await calculation of a new filter.
     */
    public int getKeyLookaheadEpoch() {
        lock.lock();
        try {
            return keyLookaheadEpoch;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Whether the keychain is married.  A keychain is married when it vends P2SH addresses
     * from multiple keychains in a multisig relationship.
     * @see
     */
    public boolean isMarried() {
        return false;
    }

   /* *//** Get redeem data for a key.  Only applicable to married keychains. *//*
    public RedeemData getRedeemData(DeterministicKey followedKey) {
        throw new UnsupportedOperationException();
    }*/

    /** Create a new key and return the matching output script.  Only applicable to married keychains. */
    public Script freshOutputScript(KeyPurpose purpose) {
        throw new UnsupportedOperationException();
    }


    /** The number of signatures required to spend coins received by this keychain. */
    public void setSigsRequiredToSpend(int sigsRequiredToSpend) {
        this.sigsRequiredToSpend = sigsRequiredToSpend;
    }

    /**
     * Returns the number of signatures required to spend transactions for this KeyChain. It's the N from
     * N-of-M CHECKMULTISIG script for P2SH transactions and always 1 for other transaction types.
     */
    public int getSigsRequiredToSpend() {
        return sigsRequiredToSpend;
    }

    /** Returns the redeem script by its hash or null if this keychain did not generate the script. */
    /*@Nullable
    public RedeemData findRedeemDataByScriptHash(ByteString bytes) {
        return null;
    }*/
}
