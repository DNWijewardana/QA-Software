// FIXTURE — intentionally insecure C# for the golden corpus (spec X.3). NOT for real use.
using System;
using System.Diagnostics;
using System.Data.SqlClient;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

class App
{
    void Run(SqlConnection conn, string name, string userInput, System.IO.Stream stream)
    {
        // this comment mentions Process.Start( and new SqlCommand( but must NOT be flagged (comment-stripping)
        Process.Start("cmd.exe /c " + userInput);                                   // SEEDED: CS-PROCESS-START-001
        var cmd = new SqlCommand("SELECT * FROM users WHERE n = '" + name + "'", conn); // SEEDED: CS-SQL-CONCAT-001
        var fmt = new BinaryFormatter();                                            // SEEDED: CS-DESERIALIZE-001
        fmt.Deserialize(stream);
        ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true; // SEEDED: CS-CERT-VALIDATION-001
        var des = DES.Create();                                                     // SEEDED: CS-WEAK-CIPHER-001
        var md5 = MD5.Create();                                                     // SEEDED: CS-WEAK-HASH-001

        // Safe patterns below must NOT be flagged:
        Process.Start("notepad.exe");                                               // literal, no injection
        var safe = new SqlCommand("SELECT 1", conn);                                // constant query
        var sha = SHA256.Create();                                                  // strong hash
    }
}
