import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SqlInjection {
    public void run(HttpServletRequest req, Connection conn) throws Exception {
        String name = req.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery(query);
    }
}
