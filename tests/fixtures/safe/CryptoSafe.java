import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public class CryptoSafe {
    public void run() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom sr = new SecureRandom();
    }
}
