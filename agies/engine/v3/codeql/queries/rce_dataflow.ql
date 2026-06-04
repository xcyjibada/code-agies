/**
 * @name RCE — remote flow to dangerous sink (dataflow)
 * @description Traces direct dataflow from remote sources to exec/eval sinks
 * @kind problem
 * @id agies/rce-dataflow
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

from DataFlow::Node source, DataFlow::Node sink
where
  source instanceof RemoteFlowSource and
  (
    exists(Call c |
      c.getFunc().(Name).getId() in ["exec", "eval", "compile"] and
      sink.asExpr() = c.getArg(0)
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["system", "popen", "call", "Popen"] and
      sink.asExpr() = c.getArg(0)
    )
  ) and
  DataFlow::localFlow(source, sink)
select sink,
  source.getLocation().getFile().getRelativePath() as source_file,
  source.getLocation().getStartLine() as source_line,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  "RCE: remote dataflow to dangerous sink"
