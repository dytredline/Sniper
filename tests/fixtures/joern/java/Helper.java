// Dosyalar arası akış: kaynak App.java, hedef burada.
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class Helper {
    public static Object load(String blob) throws Exception {
        byte[] data = java.util.Base64.getDecoder().decode(blob);
        ByteArrayInputStream bytes = new ByteArrayInputStream(data);
        ObjectInputStream in = new ObjectInputStream(bytes); // EXPECT: deserialize
        return in.readObject();
    }

    public static Object safe() throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        return in.readObject();
    }
}
