; agies CPG: Python data flow queries
;
; Captures data movement (assignments, parameter passing, returns)
; for building WRITES_TO edges in the Code Property Graph.
;
; NOTE: Only uses standard tree-sitter predicates (#eq?, #match?).

; ── Basic assignment: x = <value> ──
(assignment
  left: (identifier) @var
  right: (_) @val) @assign

; ── Augmented assignment: x += <value>, x -= <value>, etc. ──
(augmented_assignment
  left: (identifier) @var
  right: (_) @val) @aug_assign

; ── Attribute assignment: self.x = <value>, obj.attr = <value> ──
(assignment
  left: (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr)
  right: (_) @val) @attr_assign

; ── Attribute access in expression: obj.attr ──
(attribute
  object: (_) @obj
  attribute: (identifier) @attr) @attr_access

; ── Return statement: return <value> ──
(return_statement
  (_) @ret_val) @return_stmt

; ── Function call: func(<args>...) — capture the arguments ──
(call
  function: (_) @call_fn
  arguments: (argument_list
    (_) @call_arg)) @call_node

; ── Tuple/List assignment: x, y = <value> ──
(assignment
  left: (expression_list
    (_) @var)
  right: (_) @val) @tuple_assign
