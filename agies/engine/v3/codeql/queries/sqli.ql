/**
 * @name SQLI — SQL injection sinks
 * @description Finds raw SQL execution that could lead to injection
 * @kind problem
 * @id agies/sqli-sinks
 * @problem.severity error
 */

import python

class SqliSink extends Call {
  SqliSink() {
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["execute", "executemany", "executescript",
               "query", "Query", "raw_query",
               "execute_query", "run_query"]
    )
  }
}

from SqliSink c
select
  "sqli" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
