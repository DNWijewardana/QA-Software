// FIXTURE — intentionally insecure Rust for the golden corpus (spec X.3). NOT for real use.
use std::process::Command;

fn run(user_input: &str, name: &str, pool: &Pool) {
    // this comment mentions Command::new("sh") and unsafe { but must NOT be flagged (comment-stripping)
    Command::new("sh").arg("-c").arg(user_input);                                  // SEEDED: RS-COMMAND-EXEC-001
    unsafe { std::ptr::null::<u8>(); }                                             // SEEDED: RS-UNSAFE-001
    sqlx::query(&format!("SELECT * FROM users WHERE n = '{}'", name)).execute(pool); // SEEDED: RS-SQL-FORMAT-001
    let _h = Md5::new();                                                           // SEEDED: RS-WEAK-HASH-001

    // Safe patterns below must NOT be flagged:
    Command::new("ls").arg("-la");            // fixed non-shell binary
    sqlx::query("SELECT 1").execute(pool);    // constant query, no format!
    let _s = Sha256::new();                   // strong hash
}
