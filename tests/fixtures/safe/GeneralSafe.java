import java.sql.Statement;

public class GeneralSafe {
    // Mentions Statement, executeQuery, MessageDigest by name - the old
    // keyword scanner flagged all of these. A real SAST tool must not.
    public String describe(Statement st) {
        String note = "We use PreparedStatement and MessageDigest carefully.";
        return note.trim().toLowerCase();
    }

    public int add(int a, int b) {
        return a + b;
    }
}
