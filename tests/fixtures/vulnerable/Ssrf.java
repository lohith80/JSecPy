import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class Ssrf {
    public void run(HttpServletRequest req) throws Exception {
        String u = req.getParameter("url");
        URL url = new URL(u);
        url.openConnection();
    }
}
