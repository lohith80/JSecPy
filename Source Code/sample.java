import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletContext;

public class ExampleServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Get the value of a request parameter
        String paramValue = request.getParameter("paramName");

        // Get a session object
        HttpSession session = request.getSession();

        // Get a servlet context object
        ServletContext context = getServletContext();

        // Set an attribute in the request object
        request.setAttribute("attrName", "attrValue");

        // Set an attribute in the session object
        session.setAttribute("sessionAttrName", "sessionAttrValue");

        // Set an attribute in the servlet context object
        context.setAttribute("contextAttrName", "contextAttrValue");

        // Forward the request to a JSP page
        String jspPage = "/WEB-INF/jsp/example.jsp";
        request.getRequestDispatcher(jspPage).forward(request, response);

        crypto = new Crypto();
    }
}
