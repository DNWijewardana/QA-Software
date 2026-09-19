<?php
// FIXTURE — intentionally insecure PHP for the golden corpus (spec X.3). NOT for real use.

function run($pdo, $mysqli) {
    // this comment mentions eval( and system( but must NOT be flagged (comment-stripping test)
    $code = $_GET['c'];
    eval($code);                                                     // SEEDED: PHP-EVAL-001
    system('ls ' . $_GET['dir']);                                    // SEEDED: PHP-SHELL-EXEC-001
    $name = $_POST['name'];
    mysqli_query($mysqli, "SELECT * FROM users WHERE n = '" . $name . "'"); // SEEDED: PHP-SQL-CONCAT-001
    $obj = unserialize($_COOKIE['data']);                            // SEEDED: PHP-UNSERIALIZE-001
    $page = $_GET['page'];
    include($page . '.php');                                         // SEEDED: PHP-FILE-INCLUSION-001
    echo $_REQUEST['q'];                                             // SEEDED: PHP-XSS-ECHO-001
    $sig = md5($name);                                               // SEEDED: PHP-WEAK-HASH-001

    // Safe patterns below must NOT be flagged:
    $pdo->exec("CREATE TABLE t (id INT)");                           // PDO::exec (no variable) — not SQL-concat
    include 'config.php';                                            // static include — no variable
    $h = hash('sha256', $name);                                      // strong hash
}
