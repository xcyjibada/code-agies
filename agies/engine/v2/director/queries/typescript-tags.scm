; agies typescript-tags.scm
; Adapted from js-tags.scm with TS-specific adjustments:
;   - dynamic imports use call_expression(import) not import_expression

; ── def/ref queries ──

; function declarations
(function_declaration
  name: (identifier) @name.definition.function)

; arrow functions assigned to variables
(variable_declarator
  name: (identifier) @name.definition.function
  value: (arrow_function))

; method definitions
(method_definition
  name: (property_identifier) @name.definition.method)

; class declarations — TS uses type_identifier, not identifier
(class_declaration
  name: (type_identifier) @name.definition.class)

; function calls (reference)
(call_expression
  function: (identifier) @name.reference.call)

; method calls
(call_expression
  function: (member_expression
    property: (property_identifier) @name.reference.method))

; import references
(import_statement
  source: (string) @name.reference.import)

; dynamic import() — TS uses call_expression, not import_expression
(call_expression
  function: (import) @name.reference.import)

; ── SAST Signal queries ──

; SQL_SINK: db.query(), db.execute(), sequelize.query()
(call_expression
  function: (member_expression
    property: (property_identifier) @_method)
  (#match? @_method "^(query|execute|findAll|findOne|findByPk|raw)$"))
  @signal.sql_sink

; CMD_EXEC: exec(), spawn(), child_process.exec
(call_expression
  function: (identifier) @_fn
  (#match? @_fn "^(exec|spawn|fork|execSync)$"))
  @signal.cmd_exec

(call_expression
  function: (member_expression
    property: (property_identifier) @_method)
  (#match? @_method "^(exec|spawn|fork|execSync|execFile)$"))
  @signal.cmd_exec

; FILE_IO: fs.readFile, fs.writeFile, fs.existsSync
(call_expression
  function: (member_expression
    object: (identifier) @_obj
    property: (property_identifier) @_method)
  (#eq? @_obj "fs")
  (#match? @_method "^(readFile|writeFile|readFileSync|writeFileSync|existsSync|readdir|unlink|appendFile)$"))
  @signal.file_io

; NETWORK: fetch(), axios.get(), http.request()
(call_expression
  function: (identifier) @_fn
  (#eq? @_fn "fetch"))
  @signal.network_operation

; axios/http method calls — simpler pattern for TS compatibility
(call_expression
  function: (member_expression
    property: (property_identifier) @_method)
  (#match? @_method "^(get|post|put|delete|patch|request)$"))
  @signal.network_operation

; AUTH_CHECK: function names matching auth patterns
(function_declaration
  name: (identifier) @_name
  (#match? @_name "(?i)^(authenticate|authorize|verifyToken|checkRole|hasPermission|isAdmin|login|logout)$"))
  @signal.auth_check

; SERIALIZATION: JSON.parse (on untrusted data)
(call_expression
  function: (member_expression
    object: (identifier) @_obj
    property: (property_identifier) @_method)
  (#eq? @_obj "JSON")
  (#eq? @_method "parse"))
  @signal.serialization

; DYNAMIC_EXEC: eval(), Function()
(call_expression
  function: (identifier) @_fn
  (#match? @_fn "^(eval)$"))
  @signal.dynamic_exec

(new_expression
  constructor: (identifier) @_fn
  (#eq? @_fn "Function"))
  @signal.dynamic_exec
