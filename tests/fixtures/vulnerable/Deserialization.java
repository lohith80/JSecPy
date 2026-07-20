import java.io.InputStream;
import java.io.ObjectInputStream;

public class Deserialization {
    public Object run(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }
}
