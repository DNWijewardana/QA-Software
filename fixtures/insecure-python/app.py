# FIXTURE — intentionally insecure Python for the golden corpus (spec X.3). NOT for real use.
import os
import subprocess
import pickle
import yaml
import hashlib


def run(cmd, data):
    # this full-line comment mentions eval( but must NOT be flagged (comment-stripping test)
    eval(cmd)                          # SEEDED: PY-EVAL-001
    exec(cmd)                          # SEEDED: PY-EVAL-001 (exec)
    os.system(cmd)                     # SEEDED: PY-OS-SYSTEM-001
    subprocess.run(cmd, shell=True)    # SEEDED: PY-SUBPROCESS-SHELL-001
    pickle.loads(data)                 # SEEDED: PY-PICKLE-001
    yaml.load(data)                    # SEEDED: PY-YAML-LOAD-001
    hashlib.md5(data)                  # SEEDED: PY-WEAK-HASH-001


def main():
    app.run(debug=True)                # SEEDED: PY-FLASK-DEBUG-001
