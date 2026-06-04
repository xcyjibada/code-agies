/**
 * @name RCE — dangerous code execution sinks
 * @description Finds calls to exec, eval, compile, subprocess, os.system
 * @kind problem
 * @id agies/rce-sinks
 * @problem.severity error
 */

import python

/**
 * RCE sinks: functions that execute arbitrary code or commands.
 */
class RceSink extends Call {
  RceSink() {
    exists(string name |
      name = this.getFunc().(Name).getId() and
      name in ["exec", "eval", "compile"]
    )
    or
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["system", "popen", "call", "Popen", "run",
               "check_output", "check_call", "getoutput", "getstatusoutput"]
    )
  }
}

from RceSink c
select
  "rce" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
