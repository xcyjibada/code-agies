; agies CPG: Java data flow queries
;
; NOTE: Only uses standard tree-sitter predicates.

; ── Variable assignment: type x = <value>, x = <value> ──
(assignment_expression
  left: (identifier) @var
  right: (_) @val) @assign

; ── Field assignment: this.x = <value>, obj.attr = <value> ──
(assignment_expression
  left: (field_access
    object: (_) @obj
    field: (identifier) @field)
  right: (_) @val) @field_assign

; ── Variable declaration with initializer: Type x = <value> ──
(variable_declarator
  name: (identifier) @var
  value: (_) @val) @var_decl

; ── Return statement ──
(return_statement
  (_) @ret_val) @return_stmt

; ── Method call arguments ──
(method_invocation
  arguments: (argument_list
    (_) @call_arg)) @call_node

; ── Field access: obj.field ──
(field_access
  object: (_) @obj
  field: (identifier) @field) @field_access
