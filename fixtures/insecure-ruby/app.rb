# FIXTURE — intentionally insecure Ruby for the golden corpus (spec X.3). NOT for real use.
require 'yaml'
require 'digest'

def run(user_input, name, conn)
  # this comment mentions eval( and system( but must NOT be flagged (comment-stripping test)
  eval(user_input)                              # SEEDED: RB-EVAL-001
  system("rm -rf #{user_input}")                # SEEDED: RB-COMMAND-EXEC-001
  data = Marshal.load(user_input)               # SEEDED: RB-DESERIALIZE-001
  User.where("name = '#{name}'")                # SEEDED: RB-SQL-INJECTION-001
  Digest::MD5.hexdigest(name)                   # SEEDED: RB-WEAK-HASH-001

  # Safe patterns below must NOT be flagged:
  YAML.safe_load(user_input)                    # allow-listed deserialization
  User.where("name = ?", name)                  # parameterized query
  Digest::SHA256.hexdigest(name)                # strong hash
  system("ls", "-la")                           # no interpolation, argument list
  data
end
