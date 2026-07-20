import javax.servlet.http.Cookie;

public class InsecureCookie {
    public void run(Cookie cookie) {
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
    }
}
