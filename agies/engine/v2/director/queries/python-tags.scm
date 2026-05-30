; agies python-tags.scm
; Combined tree-sitter query: def/ref tags + SAST signal tags
; Based on Aider's tree-sitter-languages queries
;
; NOTE: Only uses standard tree-sitter predicates (#eq?, #match?).
; Scheme predicates (#? ...) are NOT supported by Python bindings.

; ── def/ref queries (from Aider) ──

; function definitions
(function_definition
  name: (identifier) @name.definition.function)

; function calls (reference)
(call
  function: (identifier) @name.reference.call)

; method calls via attribute
(call
  function: (attribute
    object: (identifier) @_obj
    attribute: (identifier) @name.reference.method))

; class definitions
(class_definition
  name: (identifier) @name.definition.class)

; decorators
(decorated_definition
  (decorator
    (identifier) @name.reference.call)
  .
  (function_definition
    name: (identifier) @name.definition.function))

; import statements
(import_statement
  name: (dotted_name) @name.reference.import)
(import_from_statement
  name: (dotted_name) @name.reference.import)

; ── SAST Signal queries ──

; SQL_SINK: execute(), cursor.execute(), session.query()
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#match? @_method "^(execute|query|raw_sql|executemany)$"))
  @signal.sql_sink

; SQL_SINK with chained attributes: obj.cursor.execute()
(call
  function: (attribute
    (attribute (identifier) @_obj)
    (identifier) @_method)
  (#match? @_method "^(execute|query)$"))
  @signal.sql_sink

; CMD_EXEC: os.system(), os.popen()
(call
  function: (attribute
    object: (identifier) @_obj
    attribute: (identifier) @_method)
  (#eq? @_obj "os")
  (#match? @_method "^(system|popen)$"))
  @signal.cmd_exec

; CMD_EXEC: subprocess.Popen(), subprocess.call(), subprocess.run()
(call
  function: (attribute
    object: (identifier) @_obj
    attribute: (identifier) @_method)
  (#eq? @_obj "subprocess")
  (#match? @_method "^(Popen|call|run|check_call|check_output)$"))
  @signal.cmd_exec

; FILE_IO: builtin open()
(call
  function: (identifier) @_fn
  (#eq? @_fn "open"))
  @signal.file_io

; FILE_IO: os.open()
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#eq? @_obj "os")
  (#eq? @_method "open"))
  @signal.file_io

; FILE_IO: pathlib Path methods
(call
  function: (attribute
    (attribute (identifier) @_obj)
    (identifier) @_method)
  (#match? @_method "^(read_bytes|read_text|write_bytes|write_text|open|iterdir|glob)$"))
  @signal.file_io

; REGEX: re.match(), re.search(), re.sub(), re.compile(), re.findall(), ...
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#eq? @_obj "re")
  (#match? @_method "^(match|search|sub|compile|findall|finditer|fullmatch|split)$"))
  @signal.regex_operation

; NETWORK: requests.*, httpx.*
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#match? @_obj "^(requests|httpx)$")
  (#match? @_method "^(get|post|put|delete|patch|request)$"))
  @signal.network_operation

; AUTH_CHECK: function names matching auth patterns
(function_definition
  name: (identifier) @_name
  (#match? @_name "(?i)^(authenticate|authorize|verify_token|check_role|has_permission|is_admin|login|logout)$"))
  @signal.auth_check

; CRYPTO: hashlib.*, hmac.*
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#match? @_obj "^(hashlib|hmac)$"))
  @signal.crypto_operation

; CRYPTO: jwt.encode(), jwt.decode(), jwt.verify()
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#eq? @_obj "jwt")
  (#match? @_method "^(encode|decode|verify)$"))
  @signal.crypto_operation

; SERIALIZATION: pickle.*
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#eq? @_obj "pickle")
  (#match? @_method "^(load|loads|dump|dumps)$"))
  @signal.serialization

; SERIALIZATION: yaml.load()
(call
  function: (attribute
    (identifier) @_obj
    (identifier) @_method)
  (#eq? @_obj "yaml")
  (#match? @_method "^(load|loads)$"))
  @signal.serialization

; DYNAMIC_EXEC: eval(), exec()
(call
  function: (identifier) @_fn
  (#match? @_fn "^(eval|exec)$"))
  @signal.dynamic_exec
