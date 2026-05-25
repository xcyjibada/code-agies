; agies java-tags.scm
; Combines def/ref tags + SAST signal tags

; ── def/ref queries ──

; class definitions
(class_declaration
  name: (identifier) @name.definition.class)

; method definitions
(method_declaration
  name: (identifier) @name.definition.method)

; constructor definitions
(constructor_declaration
  name: (identifier) @name.definition.method)

; method invocations (reference)
(method_invocation
  name: (identifier) @name.reference.call)

; object creations (reference)
(object_creation_expression
  type: (type_identifier) @name.reference.call)

; ── SAST Signal queries ──

; SQL_SINK: executeQuery(), executeUpdate(), Statement.execute()
(method_invocation
  name: (identifier) @_method
  (#match? @_method "^(executeQuery|executeUpdate|execute|prepareStatement|createQuery)$"))
  @signal.sql_sink

; CMD_EXEC: Runtime.exec(), ProcessBuilder
(method_invocation
  object: (identifier) @_obj
  name: (identifier) @_method
  (#eq? @_obj "Runtime")
  (#eq? @_method "exec"))
  @signal.cmd_exec

; FILE_IO: FileInputStream, FileOutputStream, Files.read/write
(method_invocation
  object: (identifier) @_obj
  name: (identifier) @_method
  (#match? @_obj "^(Files|Paths|FileUtils)$")
  (#match? @_method "^(read|write|copy|move|delete|createFile|newInputStream|newOutputStream)$"))
  @signal.file_io

; NETWORK: URL.openConnection(), HttpURLConnection, Socket
(object_creation_expression
  type: (type_identifier) @_type
  (#match? @_type "^(URL|Socket|ServerSocket|HttpURLConnection|URLConnection)$"))
  @signal.network_operation

; AUTH_CHECK: method names matching auth patterns
(method_declaration
  name: (identifier) @_name
  (#match? @_name "(?i)^(authenticate|authorize|verifyToken|checkRole|hasPermission|isAdmin|login|logout)$"))
  @signal.auth_check

; SERIALIZATION: ObjectInputStream, ObjectOutputStream, readObject
(object_creation_expression
  type: (type_identifier) @_type
  (#match? @_type "^(ObjectInputStream|ObjectOutputStream|XMLDecoder)$"))
  @signal.serialization

(method_invocation
  name: (identifier) @_method
  (#match? @_method "^(readObject|writeObject|readUnshared|writeUnshared)$"))
  @signal.serialization

; DYNAMIC_EXEC: Method.invoke(), Class.forName()
(method_invocation
  name: (identifier) @_method
  (#match? @_method "^(invoke|forName|newInstance)$"))
  @signal.dynamic_exec
