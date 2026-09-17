// FIXTURE — intentionally insecure Java for the golden corpus (spec X.3). NOT for real use.
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.io.ObjectInputStream;
import java.sql.Statement;

public class App {
    void run(Statement stmt, String name, ObjectInputStream in) throws Exception {
        // this comment mentions Runtime.getRuntime().exec( but must NOT be flagged (comment-stripping test)
        Runtime.getRuntime().exec("sh -c " + name);                       // SEEDED: JAVA-RUNTIME-EXEC-001
        stmt.executeQuery("SELECT * FROM users WHERE n = '" + name + "'"); // SEEDED: JAVA-SQL-CONCAT-001
        in.readObject();                                                  // SEEDED: JAVA-DESERIALIZE-001
        MessageDigest.getInstance("MD5");                                 // SEEDED: JAVA-WEAK-HASH-001
        Cipher.getInstance("AES/ECB/PKCS5Padding");                       // SEEDED: JAVA-ECB-001
    }
}
