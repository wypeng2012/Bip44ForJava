package party.loveit.bip44forjava.utils;



import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import party.loveit.bip44forjava.core.ChildNumber;
import party.loveit.bip44forjava.core.DeterministicKeyChain;
import party.loveit.bip44forjava.core.DeterministicSeed;
import party.loveit.bip44forjava.crypto.DeterministicKey;

public final class Bip44Utils {
    private Bip44Utils() {
    }

    /**
     * generateMnemonic 12 Words
     *
     * @param
     * @return
     * @throws Exception
     */
    public static List<String> generateMnemonicWords() throws Exception {
        MnemonicCode mnemonicCode = new MnemonicCode();

        SecureRandom secureRandom = SecureRandomUtils.secureRandom();
        byte[] initialEntropy = new byte[16];
        secureRandom.nextBytes(initialEntropy);
        List<String> wd = mnemonicCode.toMnemonic(initialEntropy);

        if (wd == null || wd.size() != 12)
            throw new RuntimeException("generate word error");
        else {
            return wd;
        }
    }

    /**
     * @param words
     * @return
     */
    public static byte[] getSeed(List<String> words) {
        return MnemonicCode.toSeed(words, "");
    }

    /**
     * @param words
     * @param path  m / purpose' / coin_type' / account' / change / address_index
     * @return
     */
    public static BigInteger getPathPrivateKey(List<String> words, String path) {
        return getDeterministicKey(words, null, path).getPrivKey();
    }

    /**
     * @param words
     * @param seed
     * @param path  m / purpose' / coin_type' / account' / change / address_index
     * @return
     */
    public static BigInteger getPathPrivateKey(List<String> words, byte[] seed, String path) {
        return getDeterministicKey(words, seed, path).getPrivKey();
    }

    /**
     * @param words
     * @param path  m / purpose' / coin_type' / account' / change / address_index
     * @return
     */
    public static byte[] getPathPrivateKeyBytes(List<String> words, String path) {
        return getDeterministicKey(words, null, path).getPrivKeyBytes();
    }

    /**
     * @param words
     * @param seed
     * @param path  m / purpose' / coin_type' / account' / change / address_index
     * @return
     */
    public static byte[] getPathPrivateKeyBytes(List<String> words, byte[] seed, String path) {
        return getDeterministicKey(words, seed, path).getPrivKeyBytes();
    }

    /**
     * @param words
     * @param coinType see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
     * @return
     */
    public static BigInteger getDefaultPathPrivateKey(List<String> words, int coinType) {
        String path = "m/44'/" +
                coinType +
                "'/0'/0/0";
        return getDeterministicKey(words, null, path).getPrivKey();
    }

    /**
     * @param words
     * @param seed
     * @param coinType see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
     * @return
     */
    public static BigInteger getDefaultPathPrivateKey(List<String> words, byte[] seed, int coinType) {
        String path = "m/44'/" +
                coinType +
                "'/0'/0/0";
        return getDeterministicKey(words, seed, path).getPrivKey();
    }

    /**
     * @param words
     * @param coinType see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
     * @return
     */
    public static byte[] getDefaultPathPrivateKeyBytes(List<String> words, int coinType) {
        String path = "m/44'/" +
                coinType +
                "'/0'/0/0";
        return getDeterministicKey(words, null, path).getPrivKeyBytes();
    }

    /**
     * @param words
     * @param seed
     * @param coinType see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
     * @return
     */
    public static byte[] getDefaultPathPrivateKeyBytes(List<String> words, byte[] seed, int coinType) {
        String path = "m/44'/" +
                coinType +
                "'/0'/0/0";
        return getDeterministicKey(words, seed, path).getPrivKeyBytes();
    }

    private static DeterministicKey getDeterministicKey(List<String> words, byte[] seed, String path) {
        DeterministicSeed deterministicSeed = new DeterministicSeed(words, seed, "", 0);
        DeterministicKeyChain deterministicKeyChain = DeterministicKeyChain.builder().seed(deterministicSeed).build();
        return deterministicKeyChain.getKeyByPath(parsePath(path), true);
    }

    private static List<ChildNumber> parsePath(@Nonnull String path) {
        String[] parsedNodes = path.replace("m", "").split("/");
        List<ChildNumber> nodes = new ArrayList<>();

        for (String n : parsedNodes) {
            n = n.replaceAll(" ", "");
            if (n.length() == 0) continue;
            boolean isHard = n.endsWith("'");
            if (isHard) n = n.substring(0, n.length() - 1);
            int nodeNumber = Integer.parseInt(n);
            nodes.add(new ChildNumber(nodeNumber, isHard));
        }

        return nodes;
    }
}
