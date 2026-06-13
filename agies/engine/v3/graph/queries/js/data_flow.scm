; agies CPG: JavaScript/TypeScript data flow queries
;
; NOTE: Only uses standard tree-sitter predicates.

; ── Variable assignment: x = <value> ──
(assignment_expression
  left: (identifier) @var
  right: (_) @val) @assign

; ── Variable declaration: let/const/var x = <value> ──
(variable_declarator
  name: (identifier) @var
  value: (_) @val) @var_decl

; ── Property assignment: obj.x = <value>, this.x = <value> ──
(assignment_expression
  left: (member_expression
    object: (_) @obj
    property: (property_identifier) @prop)
  right: (_) @val) @prop_assign

; ── Property access: obj.prop ──
(member_expression
  object: (_) @obj
  property: (property_identifier) @prop) @prop_access

; ── Return statement ──
(return_statement
  (_) @ret_val) @return_stmt

; ── Function call arguments ──
(call_expression
  arguments: (arguments
    (_) @call_arg)) @call_node
