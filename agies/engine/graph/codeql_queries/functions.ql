/**
 * @name Extract functions
 * @description Extract all user-defined function definitions with location metadata.
 */
import python

from Function f
where not f.isExtern()
select
  f.getName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine()
