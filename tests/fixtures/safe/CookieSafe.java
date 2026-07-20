import javax.servlet.http.Cookie;

public class CookieSafe {
    public void run(Cookie cookie) {
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
    }
}
