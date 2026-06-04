/**
 * @name AFO — arbitrary file overwrite sinks
 * @description Finds file write operations that could overwrite arbitrary files
 * @kind problem
 * @id agies/afo-sinks
 * @problem.severity error
 */

import python

class AfoSink extends Call {
  AfoSink() {
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["write", "writelines", "dump", "dumps",
               "save", "upload", "put", "copy", "move",
               "rename", "unlink", "remove", "rmdir",
               "mkdir", "makedirs", "symlink", "link"]
    )
    or
    exists(string name |
      name = this.getFunc().(Name).getId() and
      name in ["open"]
    )
  }
}

from AfoSink c
where
  exists(string mode |
    c.getArg(1).(StrConst).getValue() = mode and
    mode.matches("%w%")
  )
  or not exists(c.getArg(1))
select
  "afo" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
