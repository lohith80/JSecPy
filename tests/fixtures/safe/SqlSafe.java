import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SqlSafe {
    public void run(HttpServletRequest req, Connection conn) throws Exception {
        String name = req.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();
    }
}
