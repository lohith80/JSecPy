import java.security.MessageDigest;
import javax.crypto.Cipher;

public class WeakCrypto {
    public void run() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
