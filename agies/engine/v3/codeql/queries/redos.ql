/**
 * @name REDOS — ReDoS vulnerable regex operations
 * @description Finds regex compilation and matching that could lead to ReDoS
 * @kind problem
 * @id agies/redos-sinks
 * @problem.severity warning
 */

import python

class ReDoSink extends Call {
  ReDoSink() {
    exists(string name |
      name = this.getFunc().toString() and
      name in ["re.match", "re.search", "re.findall",
               "re.fullmatch", "re.sub", "re.compile",
               "re.split", "fnmatch.translate",
               "fnmatch.filter"]
    )
  }
}

from ReDoSink c
select
  "redos" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
