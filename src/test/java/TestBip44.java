import org.junit.Test;
import party.loveit.bip44forjava.utils.Bip44Utils;

import java.math.BigInteger;
import java.util.List;

public class TestBip44 {

    @Test
    public void testOne(){
        try {
            System.out.println("************ 获取12个助记词中 ************");
            List<String> words = Bip44Utils.generateMnemonicWords();
            System.out.println("12个助记词: " + words.toString() + "\n");

            System.out.println("************ 种子生成中 ************");
            byte[] seed = Bip44Utils.getSeed(words);
            System.out.println("种子: " + new BigInteger(1,seed).toString(16) + "\n");

            System.out.println("************ 根据路径获取节点私钥中 ************");
            BigInteger pri1 = Bip44Utils.getPathPrivateKey(words,"m/44'/60'/0'/0/0");
            System.out.println("路径私钥: " + pri1.toString(16) + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
