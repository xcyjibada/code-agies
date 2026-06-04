/**
 * @name LFI — file access sinks
 * @description Finds file read/open operations that could lead to path traversal
 * @kind problem
 * @id agies/lfi-sinks
 * @problem.severity error
 */

import python

class LfiSink extends Call {
  LfiSink() {
    exists(string name |
      name = this.getFunc().(Name).getId() and
      name in ["open", "file"]
    )
    or
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["read", "read_text", "read_bytes", "open", "write",
               "resolve", "joinpath"]
    )
  }
}

from LfiSink c
select
  "lfi" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
