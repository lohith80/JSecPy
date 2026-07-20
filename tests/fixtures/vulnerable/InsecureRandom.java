import java.util.Random;

public class InsecureRandom {
    public String token() {
        Random r = new Random();
        double d = Math.random();
        return Long.toString(r.nextLong());
    }
}
