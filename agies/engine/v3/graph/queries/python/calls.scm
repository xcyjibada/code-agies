; agies CPG: Python call graph queries
;
; Captures function/method calls for building CALLS edges.
; NOTE: Only uses standard tree-sitter predicates.

; ── Simple function call: func(...) ──
(call
  function: (identifier) @caller
  arguments: (argument_list) @args) @simple_call

; ── Method call via attribute: obj.method(...) ──
(call
  function: (attribute
    object: (_) @object
    attribute: (identifier) @method)
  arguments: (argument_list) @args) @method_call

; ── Chained call: obj.method1().method2() ──
; The outer call's function is an attribute whose object is another call
(call
  function: (attribute
    object: (call) @chain_call
    attribute: (identifier) @method)) @chained_call

; ── Function definition ──
(function_definition
  name: (identifier) @name) @func_def

; ── Class method definition ──
; (function_definition inside class_definition)
(class_definition
  name: (identifier) @class_name
  body: (block
    (function_definition
      name: (identifier) @method_name) @method_def)) @class_def
