/**
 * @name XSS — cross-site scripting sinks
 * @description Finds HTML/template rendering with unsanitized data
 * @kind problem
 * @id agies/xss-sinks
 * @problem.severity error
 */

import python

class XssSink extends Call {
  XssSink() {
    exists(string name |
      name = this.getFunc().(Attribute).getName() and
      name in ["render", "render_template", "render_template_string",
               "format", "write", "Response", "make_response",
               "jsonify", "send_file", "send_from_directory"]
    )
  }
}

from XssSink c
select
  "xss" as sink_type,
  c.getFile().getRelativePath() as sink_file,
  c.getLocation().getStartLine() as sink_line,
  c.getFunc().toString() as sink_name
