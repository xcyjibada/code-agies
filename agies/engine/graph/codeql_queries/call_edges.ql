/**
 * @name Extract call edges
 * @description Extract resolved call edges between functions within the same project.
 */
import python

from Call c, Function caller, Function callee
where
  c.getEnclosingFunction() = caller and
  c.getTarget() = callee and
  caller != callee
select
  caller.getName(),
  caller.getFile().getRelativePath(),
  caller.getLocation().getStartLine(),
  callee.getName(),
  callee.getFile().getRelativePath(),
  callee.getLocation().getStartLine()
