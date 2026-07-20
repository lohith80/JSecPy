import javax.naming.directory.DirContext;
import javax.xml.xpath.XPath;
import javax.servlet.http.HttpServletRequest;

public class LdapXpath {
    public void run(DirContext ctx, XPath xp, HttpServletRequest req) throws Exception {
        String u = req.getParameter("u");
        ctx.search("ou=people", "(uid=" + u + ")", null);
        xp.compile("/users/user[@name='" + u + "']");
    }
}
