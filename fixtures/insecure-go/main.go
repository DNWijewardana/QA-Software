// FIXTURE — intentionally insecure Go for the golden corpus (spec X.3). NOT for real use.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"os/exec"
)

func run(db *sql.DB, name string) {
	// this comment mentions InsecureSkipVerify: true but must NOT be flagged (comment-stripping test)
	cfg := &tls.Config{InsecureSkipVerify: true} // SEEDED: GO-TLS-INSECURE-001
	_ = cfg
	exec.Command("sh", "-c", name) // SEEDED: GO-EXEC-SHELL-001
	db.Query("SELECT * FROM users WHERE name = '" + name + "'") // SEEDED: GO-SQL-CONCAT-001
	md5.New() // SEEDED: GO-WEAK-HASH-001
}
