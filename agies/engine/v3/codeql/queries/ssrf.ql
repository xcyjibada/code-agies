/**
 * @name SSRF — server-side request forgery sinks
 * @description Finds outbound HTTP request functions
 * @kind problem
 * @id agies/ssrf-sinks
 * @problem.severity error
 */

import python

class SsrfSink extends Call {
  SsrfSink() {
    exists(string name |
      name = this.getFunc().(Name).getId() and
      name in ["urlopen", "urlretrieve"]
    )
    or
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["request", "urlopen", "urlretrieve", "get", "post",
               "put", "delete", "patch", "head", "options",
               "Request", "UrlRequest", "fetch"]
    )
  }
}

from SsrfSink c
select
  "ssrf" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
