/**
 * @name IDOR — insecure direct object reference sinks
 * @description Finds direct object access patterns that could allow unauthorized access
 * @kind problem
 * @id agies/idor-sinks
 * @problem.severity error
 */

import python

class IdorSink extends Call {
  IdorSink() {
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["get", "get_object", "get_object_or_404",
               "get_queryset", "filter", "exclude",
               "get_by_natural_key", "lookup",
               "retrieve", "fetch", "query",
               "find_by_id", "find_by_pk",
               "QuerySet", "Model.objects"]
    )
  }
}

from IdorSink c
select
  "idor" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
