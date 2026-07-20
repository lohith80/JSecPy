import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public void run(HttpServletRequest req) throws Exception {
        String p = req.getParameter("file");
        File f = new File(p);
        FileInputStream in = new FileInputStream(p);
    }
}
