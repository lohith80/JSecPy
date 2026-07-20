import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;

public class TrustAllTls {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }
}
