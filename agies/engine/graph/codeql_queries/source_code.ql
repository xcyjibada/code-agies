/**
 * @name Extract source code
 * @description Extract the source text and signature for each function.
 */
import python

from Function f
where not f.isExtern()
select
  f.getName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine(),
  f.getSignature().toString()
