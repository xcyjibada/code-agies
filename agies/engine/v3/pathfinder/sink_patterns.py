"""Sink function name patterns → vulnerability type mapping.

Used by ``TreeSitterPathFinder`` and also sharable with CodeQL-based path
discovery.  Maps function names (and patterns) to vulnerability types so
the pathfinder can classify sinks it finds in the call graph.
"""

from __future__ import annotations

import re

from agies.engine.v3.codeql.models import VulnType

# ---------------------------------------------------------------------------
# Sink name → VulnType mapping
# ---------------------------------------------------------------------------
# A function whose name matches any of these is considered a sink of the
# corresponding vulnerability type.
#
# Structure: list of (exact_name | exact_method, VulnType)
# where exact_name matches simple names like "exec",
# and exact_method matches qualified names like "subprocess.call".

EXACT_SINKS: list[tuple[str, VulnType]] = [
    # -- RCE: code / command execution --
    ("exec", VulnType.RCE),
    ("eval", VulnType.RCE),
    ("__import__", VulnType.RCE),
    ("os.system", VulnType.RCE),
    ("os.popen", VulnType.RCE),
    ("subprocess.call", VulnType.RCE),
    ("subprocess.Popen", VulnType.RCE),
    ("subprocess.run", VulnType.RCE),
    ("subprocess.check_call", VulnType.RCE),
    ("subprocess.check_output", VulnType.RCE),
    ("subprocess.getoutput", VulnType.RCE),
    ("subprocess.getstatusoutput", VulnType.RCE),
    ("popen", VulnType.RCE),
    ("check_output", VulnType.RCE),
    # -- RCE: Go command execution --
    ("os/exec.Command", VulnType.RCE),
    ("os/exec.CommandContext", VulnType.RCE),
    ("exec.Command", VulnType.RCE),
    # -- Deserialization RCE --
    ("pickle.loads", VulnType.RCE),
    ("pickle.load", VulnType.RCE),
    ("cloudpickle.loads", VulnType.RCE),
    ("cloudpickle.load", VulnType.RCE),
    ("yaml.load", VulnType.RCE),
    ("yaml.unsafe_load", VulnType.RCE),
    ("marshal.loads", VulnType.RCE),
    ("marshal.load", VulnType.RCE),
    # -- msgpack deserialization --
    ("msgpack.unpackb", VulnType.RCE),
    ("msgpack.unpack", VulnType.RCE),
    # -- LanGraph-specific: msgpack ext_hook deserialization RCE --
    ("importlib.import_module", VulnType.LANGGRAPH),
    ("ormsgpack.unpackb", VulnType.LANGGRAPH),
    ("lg_msgpack.unpackb", VulnType.LANGGRAPH),
    ("jsonplus.loads_typed", VulnType.LANGGRAPH),
    ("jsonplus.dumps_typed", VulnType.LANGGRAPH),
    ("serialized_value_from_proto", VulnType.LANGGRAPH),
    # -- LangGraph-specific: gRPC no-auth endpoints --
    ("RegisterAdminServer", VulnType.LANGGRAPH),
    ("RegisterAssistantsServer", VulnType.LANGGRAPH),
    ("RegisterCacheServer", VulnType.LANGGRAPH),
    ("RegisterCronsServer", VulnType.LANGGRAPH),
    ("RegisterRunsServer", VulnType.LANGGRAPH),
    ("RegisterThreadsServer", VulnType.LANGGRAPH),
    ("RegisterCheckpointerServer", VulnType.LANGGRAPH),
    # -- LangGraph-specific: dangerous admin operations --
    ("adminServerImpl.Truncate", VulnType.LANGGRAPH),
    ("TruncateRequest", VulnType.LANGGRAPH),
    # -- LangGraph-specific: template injection --
    ("renderHeaderTemplate", VulnType.LANGGRAPH),
    ("headerTemplateRe", VulnType.LANGGRAPH),
    # -- LangGraph-specific: crypto --
    ("NewAESEncryptor", VulnType.LANGGRAPH),
    ("AESEncryptor.Encrypt", VulnType.LANGGRAPH),
    ("AESEncryptor.Decrypt", VulnType.LANGGRAPH),
    ("AESEncryptor.EncryptJSON", VulnType.LANGGRAPH),
    # -- LFI: file read --
    ("open", VulnType.LFI),
    ("pathlib.Path.open", VulnType.LFI),
    ("pathlib.Path.read_text", VulnType.LFI),
    ("pathlib.Path.read_bytes", VulnType.LFI),
    ("file", VulnType.LFI),
    # -- SSRF: outbound HTTP --
    ("urlopen", VulnType.SSRF),
    ("urlretrieve", VulnType.SSRF),
    ("urllib.request.urlopen", VulnType.SSRF),
    ("urllib.request.urlretrieve", VulnType.SSRF),
    ("httpx.Client", VulnType.SSRF),
    ("httpx.AsyncClient", VulnType.SSRF),
    ("aiohttp.ClientSession", VulnType.SSRF),
    # -- SQLI: database queries --
    ("execute", VulnType.SQLI),
    ("executemany", VulnType.SQLI),
    ("executescript", VulnType.SQLI),
    # -- XSS: output rendering --
    ("Markup", VulnType.XSS),
    # -- XXE: XML parsing with insecure defaults --
    ("xml.etree.ElementTree.parse", VulnType.XXE),
    ("xml.etree.ElementTree.fromstring", VulnType.XXE),
    ("lxml.etree.parse", VulnType.XXE),
    ("lxml.etree.fromstring", VulnType.XXE),
    ("lxml.etree.XMLParser", VulnType.XXE),
    ("xml.dom.minidom.parse", VulnType.XXE),
    ("xml.dom.minidom.parseString", VulnType.XXE),
    ("xml.sax.parse", VulnType.XXE),
    ("xml.sax.parseString", VulnType.XXE),
    ("lxml.objectify.parse", VulnType.XXE),
    ("lxml.objectify.fromstring", VulnType.XXE),
    # -- SSTI: template injection (Jinja2 / Mako / Django) --
    ("render_template_string", VulnType.SSTI),
    ("jinja2.Template", VulnType.SSTI),
    ("jinja2.Environment", VulnType.SSTI),
    ("Template", VulnType.SSTI),  # string.Template FP possible — LLM filters it
    ("Template.render", VulnType.SSTI),
    ("Environment.from_string", VulnType.SSTI),
    ("mako.template.Template", VulnType.SSTI),
    # -- AFO: file write --
    ("pathlib.Path.write_text", VulnType.AFO),
    ("pathlib.Path.write_bytes", VulnType.AFO),
    ("shutil.copy", VulnType.AFO),
    ("shutil.move", VulnType.AFO),
    ("os.remove", VulnType.AFO),
    ("os.unlink", VulnType.AFO),
    # -- ML / AI framework sinks --
    # PyTorch: torch.load without weights_only → RCE
    ("torch.load", VulnType.RCE),
    ("torch.hub.load", VulnType.RCE),
    ("torch.hub.download_url_to_file", VulnType.SSRF),
    # HuggingFace: from_pretrained loads arbitrary code from hub
    ("AutoModel.from_pretrained", VulnType.RCE),
    ("AutoModelForSequenceClassification.from_pretrained", VulnType.RCE),
    ("AutoModelForCausalLM.from_pretrained", VulnType.RCE),
    ("AutoTokenizer.from_pretrained", VulnType.RCE),
    ("transformers.pipeline", VulnType.RCE),
    ("pipeline", VulnType.RCE),
    # safetensors: file path can be controlled → arbitrary file write/read
    ("safetensors.torch.load_file", VulnType.AFO),
    # ONNX: model binary could embed malicious operations
    ("onnxruntime.InferenceSession", VulnType.RCE),
    # joblib / skops: model serialization deserialization
    ("joblib.load", VulnType.RCE),
    ("skops.load", VulnType.RCE),
    ("skops.io.visualization.load", VulnType.RCE),
    # MLflow: model loading from artifact stores
    ("mlflow.pyfunc.load_model", VulnType.RCE),
    ("mlflow.pytorch.load_model", VulnType.RCE),
    ("mlflow.huggingface.load_model", VulnType.RCE),
    # TensorFlow / Keras: loading models with custom layers
    ("tf.keras.models.load_model", VulnType.RCE),
    ("tensorflow.keras.models.load_model", VulnType.RCE),
    # numpy: allow_pickle=True → deserialization RCE
    ("numpy.load", VulnType.RCE),
    # -- REDOS: regex / pattern matching --
    ("glob", VulnType.REDOS),
    ("fnmatch.translate", VulnType.REDOS),
    ("fnmatch.filter", VulnType.REDOS),
    ("re.match", VulnType.REDOS),
    ("re.search", VulnType.REDOS),
    ("re.findall", VulnType.REDOS),
    ("re.fullmatch", VulnType.REDOS),
    ("re.sub", VulnType.REDOS),
    ("re.compile", VulnType.REDOS),
    # ======================================================================
    # Java RCE: command execution
    # ======================================================================
    ("Runtime.exec", VulnType.RCE),
    ("Runtime.getRuntime.exec", VulnType.RCE),
    ("java.lang.Runtime.exec", VulnType.RCE),
    ("ProcessBuilder", VulnType.RCE),
    ("ProcessBuilder.start", VulnType.RCE),
    ("java.lang.ProcessBuilder", VulnType.RCE),
    ("java.lang.ProcessBuilder.start", VulnType.RCE),
    # Java RCE: script engine
    ("ScriptEngine.eval", VulnType.RCE),
    ("javax.script.ScriptEngine.eval", VulnType.RCE),
    ("ScriptEngineManager.getEngineByName", VulnType.RCE),
    ("javax.script.ScriptEngineManager.getEngineByName", VulnType.RCE),
    # Java RCE: SpEL / expression injection
    ("SpelExpressionParser.parseExpression", VulnType.RCE),
    ("org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression", VulnType.RCE),
    ("SpelExpressionParser.parseRaw", VulnType.RCE),
    ("org.springframework.expression.Expression.getValue", VulnType.RCE),
    # Java RCE: OGNL (Struts2, etc.)
    ("Ognl.getValue", VulnType.RCE),
    ("Ognl.parseExpression", VulnType.RCE),
    ("ognl.Ognl.getValue", VulnType.RCE),
    ("ognl.Ognl.parseExpression", VulnType.RCE),
    # Java RCE: MVEL
    ("MVEL.eval", VulnType.RCE),
    ("MVEL.executeExpression", VulnType.RCE),
    ("org.mvel2.MVEL.eval", VulnType.RCE),
    ("org.mvel2.MVEL.executeExpression", VulnType.RCE),
    # Java RCE: JEXL (Apache Commons)
    ("JexlEngine.createExpression", VulnType.RCE),
    ("JexlExpression.evaluate", VulnType.RCE),
    ("org.apache.commons.jexl3.JexlEngine.createExpression", VulnType.RCE),
    ("org.apache.commons.jexl3.JexlExpression.evaluate", VulnType.RCE),
    # Java RCE: EL injection
    ("ELProcessor.eval", VulnType.RCE),
    ("javax.el.ELProcessor.eval", VulnType.RCE),
    ("javax.el.ELContext.eval", VulnType.RCE),
    ("jakarta.el.ELProcessor.eval", VulnType.RCE),
    # Java RCE: JNDI injection
    ("InitialContext.lookup", VulnType.RCE),
    ("javax.naming.InitialContext.lookup", VulnType.RCE),
    ("Context.lookup", VulnType.RCE),
    ("javax.naming.Context.lookup", VulnType.RCE),
    # Java RCE: method reflection
    ("Method.invoke", VulnType.RCE),
    ("java.lang.reflect.Method.invoke", VulnType.RCE),
    # Java RCE: deserialization
    ("ObjectInputStream.readObject", VulnType.RCE),
    ("java.io.ObjectInputStream.readObject", VulnType.RCE),
    ("ObjectInputStream.readUnshared", VulnType.RCE),
    ("java.io.ObjectInputStream.readUnshared", VulnType.RCE),
    ("ObjectMapper.enableDefaultTyping", VulnType.RCE),
    ("com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping", VulnType.RCE),
    ("org.codehaus.jackson.map.ObjectMapper.enableDefaultTyping", VulnType.RCE),
    ("SnakeYaml.load", VulnType.RCE),
    ("org.yaml.snakeyaml.Yaml.load", VulnType.RCE),
    ("XStream.fromXML", VulnType.RCE),
    ("com.thoughtworks.xstream.XStream.fromXML", VulnType.RCE),
    ("Beans.instantiate", VulnType.RCE),
    ("java.beans.Beans.instantiate", VulnType.RCE),
    # Java RCE: native library loading
    ("Runtime.load", VulnType.RCE),
    ("Runtime.loadLibrary", VulnType.RCE),
    ("java.lang.Runtime.load", VulnType.RCE),
    ("java.lang.Runtime.loadLibrary", VulnType.RCE),
    # Java SSTI: Freemarker
    ("freemarker.template.Template.process", VulnType.SSTI),
    ("Template.process", VulnType.SSTI),
    # Java SSTI: Velocity
    ("Velocity.evaluate", VulnType.SSTI),
    ("VelocityEngine.evaluate", VulnType.SSTI),
    ("org.apache.velocity.app.Velocity.evaluate", VulnType.SSTI),
    ("org.apache.velocity.app.VelocityEngine.evaluate", VulnType.SSTI),
    # Java SSTI: Thymeleaf
    ("TemplateEngine.process", VulnType.SSTI),
    ("org.thymeleaf.TemplateEngine.process", VulnType.SSTI),
    ("SPELVariableExpressionEvaluator", VulnType.SSTI),
    # Java SSTI: Pebble
    ("PebbleEngine.getTemplate", VulnType.SSTI),
    ("pebble.PebbleEngine.getTemplate", VulnType.SSTI),
    # Java SSTI: Jade4j / Pug
    ("JadeConfiguration.getTemplate", VulnType.SSTI),
    ("PugConfiguration.getTemplate", VulnType.SSTI),
    # Java SSTI: Groovy (embedded in templates)
    ("groovy.lang.GroovyShell.evaluate", VulnType.RCE),
    ("GroovyShell.evaluate", VulnType.RCE),
    ("groovy.lang.GroovyShell.parse", VulnType.RCE),
    # ======================================================================
    # Java LFI / path traversal
    # ======================================================================
    ("java.io.FileInputStream", VulnType.LFI),
    ("FileInputStream", VulnType.LFI),
    ("java.io.FileReader", VulnType.LFI),
    ("FileReader", VulnType.LFI),
    ("java.nio.file.Files.readString", VulnType.LFI),
    ("java.nio.file.Files.readAllBytes", VulnType.LFI),
    ("java.nio.file.Files.readAllLines", VulnType.LFI),
    ("java.nio.file.Files.newInputStream", VulnType.LFI),
    ("java.io.RandomAccessFile", VulnType.SUSPICIOUS),  # read or write
    ("org.apache.commons.io.FileUtils.readFileToString", VulnType.LFI),
    ("org.apache.commons.io.FileUtils.readLines", VulnType.LFI),
    ("org.apache.commons.io.IOUtils.toString", VulnType.LFI),  # from FileInputStream
    ("java.util.Scanner", VulnType.LFI),  # Scanner(File)
    # Spring ResourceLoader
    ("ResourceLoader.getResource", VulnType.LFI),
    ("org.springframework.core.io.ResourceLoader.getResource", VulnType.LFI),
    ("ClassPathResource", VulnType.LFI),
    ("org.springframework.core.io.ClassPathResource", VulnType.LFI),
    ("FileUrlResource", VulnType.LFI),
    ("org.springframework.core.io.FileUrlResource", VulnType.LFI),
    # Java NIO Path (used with Files.read*)
    ("java.nio.file.Paths.get", VulnType.LFI),
    ("Paths.get", VulnType.LFI),
    # ======================================================================
    # Java SSRF
    # ======================================================================
    ("java.net.URL.openConnection", VulnType.SSRF),
    ("java.net.URL.openStream", VulnType.SSRF),
    ("URL.openConnection", VulnType.SSRF),
    ("URL.openStream", VulnType.SSRF),
    ("java.net.HttpURLConnection", VulnType.SSRF),
    ("javax.net.ssl.HttpsURLConnection", VulnType.SSRF),
    ("org.apache.http.client.methods.HttpGet", VulnType.SSRF),
    ("org.apache.http.client.methods.HttpPost", VulnType.SSRF),
    ("org.apache.http.impl.client.CloseableHttpClient.execute", VulnType.SSRF),
    ("CloseableHttpClient.execute", VulnType.SSRF),
    ("okhttp3.OkHttpClient.newCall", VulnType.SSRF),
    ("OkHttpClient.newCall", VulnType.SSRF),
    ("okhttp3.Request.Builder.url", VulnType.SSRF),
    ("okhttp3.Request.Builder", VulnType.SSRF),
    ("com.squareup.okhttp.OkHttpClient.execute", VulnType.SSRF),
    ("java.net.Socket", VulnType.SSRF),
    ("java.net.Socket.connect", VulnType.SSRF),
    ("org.springframework.web.client.RestTemplate.exchange", VulnType.SSRF),
    ("org.springframework.web.client.RestTemplate.getForObject", VulnType.SSRF),
    ("org.springframework.web.client.RestTemplate.postForObject", VulnType.SSRF),
    ("RestTemplate.exchange", VulnType.SSRF),
    ("RestTemplate.getForObject", VulnType.SSRF),
    ("org.springframework.web.reactive.function.client.WebClient.create", VulnType.SSRF),
    ("WebClient.create", VulnType.SSRF),
    ("org.apache.cxf.jaxrs.client.WebClient", VulnType.SSRF),
    # ======================================================================
    # Java SQLI
    # ======================================================================
    ("java.sql.Statement.executeQuery", VulnType.SQLI),
    ("java.sql.Statement.execute", VulnType.SQLI),
    ("java.sql.Statement.executeUpdate", VulnType.SQLI),
    ("java.sql.Connection.prepareStatement", VulnType.SUSPICIOUS),  # only if concatenated
    ("org.springframework.jdbc.core.JdbcTemplate.execute", VulnType.SQLI),
    ("org.springframework.jdbc.core.JdbcTemplate.query", VulnType.SQLI),
    ("org.springframework.jdbc.core.JdbcTemplate.queryForList", VulnType.SQLI),
    ("org.springframework.jdbc.core.JdbcTemplate.queryForMap", VulnType.SQLI),
    ("JdbcTemplate.execute", VulnType.SQLI),
    ("org.hibernate.Session.createQuery", VulnType.SQLI),   # HQL injection
    ("org.hibernate.Session.createSQLQuery", VulnType.SQLI), # native SQL injection
    ("javax.persistence.EntityManager.createNativeQuery", VulnType.SQLI),
    ("jakarta.persistence.EntityManager.createNativeQuery", VulnType.SQLI),
    ("javax.persistence.EntityManager.createQuery", VulnType.SQLI),
    ("EntityManager.createNativeQuery", VulnType.SQLI),
    ("org.mybatis.spring.SqlSessionTemplate.selectList", VulnType.SQLI),
    ("org.mybatis.spring.SqlSessionTemplate.selectOne", VulnType.SQLI),
    ("org.mybatis.spring.SqlSessionTemplate.insert", VulnType.SQLI),
    ("SqlSessionTemplate.selectList", VulnType.SQLI),
    # ======================================================================
    # Java XXE
    # ======================================================================
    ("javax.xml.parsers.DocumentBuilderFactory.newDocumentBuilder", VulnType.XXE),
    ("DocumentBuilderFactory.newDocumentBuilder", VulnType.XXE),
    ("DocumentBuilder.parse", VulnType.XXE),
    ("javax.xml.parsers.SAXParser.parse", VulnType.XXE),
    ("SAXParser.parse", VulnType.XXE),
    ("org.xml.sax.helpers.XMLReaderFactory.createXMLReader", VulnType.XXE),
    ("XMLReader.parse", VulnType.XXE),
    ("org.dom4j.io.SAXReader.read", VulnType.XXE),
    ("SAXReader.read", VulnType.XXE),
    ("org.jdom2.input.SAXBuilder.build", VulnType.XXE),
    ("SAXBuilder.build", VulnType.XXE),
    ("javax.xml.stream.XMLInputFactory.createXMLEventReader", VulnType.XXE),
    ("javax.xml.stream.XMLInputFactory.createXMLStreamReader", VulnType.XXE),
    ("XMLInputFactory.createXMLEventReader", VulnType.XXE),
    ("XMLInputFactory.createXMLStreamReader", VulnType.XXE),
    ("org.apache.commons.digester3.Digester.parse", VulnType.XXE),
    ("javax.xml.bind.Unmarshaller.unmarshal", VulnType.XXE),  # JAXB XXE
    ("com.fasterxml.jackson.dataformat.xml.XmlMapper", VulnType.XXE),
    ("XmlMapper", VulnType.XXE),
    # ======================================================================
    # Java AFO / file write / zip slip
    # ======================================================================
    ("java.io.FileOutputStream", VulnType.AFO),
    ("FileOutputStream", VulnType.AFO),
    ("java.io.FileWriter", VulnType.AFO),
    ("FileWriter", VulnType.AFO),
    ("java.nio.file.Files.write", VulnType.AFO),
    ("java.nio.file.Files.copy", VulnType.AFO),
    ("java.nio.file.Files.move", VulnType.AFO),
    ("java.nio.file.Files.delete", VulnType.AFO),
    ("java.nio.file.Files.createFile", VulnType.AFO),
    ("java.nio.file.Files.createDirectory", VulnType.AFO),
    ("java.io.File.createNewFile", VulnType.AFO),
    ("org.apache.commons.io.FileUtils.writeByteArrayToFile", VulnType.AFO),
    ("org.apache.commons.io.FileUtils.copyFile", VulnType.AFO),
    ("org.apache.commons.io.FileUtils.deleteQuietly", VulnType.AFO),
    ("org.apache.commons.io.FileUtils.moveFile", VulnType.AFO),
    ("java.util.zip.ZipFile.extractAll", VulnType.AFO),
    ("java.util.zip.ZipEntry", VulnType.AFO),
    # ======================================================================
    # Java XSS
    # ======================================================================
    ("HttpServletResponse.getWriter", VulnType.XSS),
    ("javax.servlet.http.HttpServletResponse.getWriter", VulnType.XSS),
    ("jakarta.servlet.http.HttpServletResponse.getWriter", VulnType.XSS),
    ("PrintWriter.write", VulnType.XSS),
    ("java.io.PrintWriter.write", VulnType.XSS),
    ("PrintWriter.print", VulnType.XSS),
    ("ModelAndView.addObject", VulnType.XSS),  # reflected in template
    # ======================================================================
    # Java REDOS
    # ======================================================================
    ("java.util.regex.Pattern.compile", VulnType.REDOS),
    ("java.util.regex.Pattern.matches", VulnType.REDOS),
    ("Pattern.compile", VulnType.REDOS),
    ("java.util.regex.Matcher.matches", VulnType.REDOS),
    ("java.util.regex.Matcher.find", VulnType.REDOS),
    ("org.apache.commons.lang3.RegExUtils", VulnType.REDOS),
    ("String.matches", VulnType.REDOS),
    ("String.replaceAll", VulnType.REDOS),
    ("String.replaceFirst", VulnType.REDOS),
    ("String.split", VulnType.REDOS),
]

# ---------------------------------------------------------------------------
# Regex patterns — catch sink-like names that are not exact matches
# ---------------------------------------------------------------------------

SINK_REGEX: list[tuple[re.Pattern, VulnType]] = [
    # RCE: any function with "exec" or "eval" in name
    (re.compile(r"^(?:safe_|unsafe_)?exec(?:ute(?:_command)?)?$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"^(?:safe_|unsafe_)?eval$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"^popen$", re.IGNORECASE), VulnType.RCE),
    # LFI: read-like functions
    (re.compile(r"^(read_file|read_text|read_bytes|load_file|get_file)$", re.IGNORECASE), VulnType.LFI),
    # SSRF: fetch/get/request
    (re.compile(r"^(http_request|make_request|do_request)$", re.IGNORECASE), VulnType.SSRF),
    # SQLI: query-like
    (re.compile(r"^(query|raw_query|run_query|native_query|execute_query)$", re.IGNORECASE), VulnType.SQLI),
    # Java: Runtime.exec calls with various signatures
    (re.compile(r"\bexec\b", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"\bProcessBuilder\b", re.IGNORECASE), VulnType.RCE),
    # Java: JNDI lookups
    (re.compile(r".*InitialContext\.lookup.*", re.IGNORECASE), VulnType.RCE),
    (re.compile(r".*Context\.lookup.*", re.IGNORECASE), VulnType.RCE),
    # Java: Deserialization readObject
    (re.compile(r"readObject$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"readUnshared$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"fromXML$", re.IGNORECASE), VulnType.RCE),
    # Java: URL.openStream / openConnection
    (re.compile(r"openConnection$", re.IGNORECASE), VulnType.SSRF),
    (re.compile(r"openStream$", re.IGNORECASE), VulnType.SSRF),
    (re.compile(r"newCall$", re.IGNORECASE), VulnType.SSRF),
]

# ---------------------------------------------------------------------------
# Known entry-point function name patterns
# ---------------------------------------------------------------------------

ENTRY_POINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(get|post|put|delete|patch|head|options)$", re.IGNORECASE),
    re.compile(r"^handle_.*", re.IGNORECASE),
    re.compile(r"^on_.*", re.IGNORECASE),
    re.compile(r".*_handler$", re.IGNORECASE),
    re.compile(r".*_route$", re.IGNORECASE),
    re.compile(r"^main$"),
    re.compile(r"^run$"),
    re.compile(r"^serve$"),
    re.compile(r"^start$"),
    re.compile(r"^dispatch$"),
]


def classify_sink(name: str) -> VulnType | None:
    """Classify a function name as a sink of a specific vulnerability type.

    Returns ``None`` if the name does not match any known sink pattern.

    Priority order for exact matches:
    1. Full ``name == pattern``
    2. Qualified suffix match (both name and pattern contain ``.``)
    3. Bare suffix match (name contains ``.``, pattern doesn't)
    """
    # 1. Exact full match
    for pattern, vuln_type in EXACT_SINKS:
        if name == pattern:
            return vuln_type

    has_dot = "." in name

    # 2. Qualified suffix match — when name has a dot, prefer patterns
    #    that also have dots (e.g. ``CloseableHttpClient.execute`` wins
    #    over bare ``execute`` for a name with dots).
    if has_dot:
        for pattern, vuln_type in EXACT_SINKS:
            if "." in pattern and name.endswith(f".{pattern}"):
                return vuln_type

    # 3. Bare suffix match — fallback for names that still have a dot
    #    but didn't match any qualified pattern
    for pattern, vuln_type in EXACT_SINKS:
        if "." not in pattern and name.endswith(f".{pattern}"):
            return vuln_type

    # 4. Regex check
    for pattern, vuln_type in SINK_REGEX:
        if pattern.match(name):
            return vuln_type

    return None


def is_entry_point(name: str) -> bool:
    """Check whether a function name looks like an entry point."""
    return any(p.match(name) for p in ENTRY_POINT_PATTERNS)


KNOWN_SINK_NAMES: set[str] = {name for name, _ in EXACT_SINKS}
"""Set of all known exact sink names, for quick lookup."""

# ---------------------------------------------------------------------------
# Sensitive call patterns — functions whose *body* calls these are candidates
# for Explore slots even if their name doesn't match a known sink.
# ---------------------------------------------------------------------------
# These catch logic vulnerabilities like path traversal, permission bypass,
# and missing validation — things that don't have a single dangerous sink
# function but involve sensitive operations on untrusted data.

SENSITIVE_CALL_PATTERNS: list[tuple[re.Pattern, VulnType]] = [
    # -- XXE / XML Entity Expansion (CWE-611) --
    # XXE occurs when XML parsers with insecure defaults process untrusted
    # XML input, allowing DTD entity expansion, file exfiltration, and SSRF.
    # High confidence: XML parsing of untrusted data with default settings
    # is almost always exploitable.
    (re.compile(r"xml\.etree\.ElementTree\.(?:parse|fromstring)"), VulnType.XXE),
    (re.compile(r"lxml\.etree\.(?:parse|fromstring|XMLParser)"), VulnType.XXE),
    (re.compile(r"xml\.dom\.minidom\.(?:parse|parseString)"), VulnType.XXE),
    (re.compile(r"xml\.sax\.(?:parse|parseString)"), VulnType.XXE),
    (re.compile(r"BeautifulSoup\(.*['\"]xml['\"]"), VulnType.XXE),
    (re.compile(r"lxml\.objectify\.(?:fromstring|parse)"), VulnType.XXE),
    # Common import aliases: from xml.etree import ElementTree; ElementTree.fromstring(...)
    (re.compile(r"ElementTree\.(?:parse|fromstring)"), VulnType.XXE),
    (re.compile(r"etree\.(?:parse|fromstring|XMLParser)"), VulnType.XXE),
    # -- SSTI: Server-Side Template Injection (CWE-1336) --
    # User input flowing into template engines without sanitization can
    # lead to RCE via Jinja2 sandbox escapes, Mako arbitrary code execution,
    # or Django template variable leakage.
    (re.compile(r"render_template_string\s*\("), VulnType.SSTI),
    (re.compile(r"\bTemplate\s*\("), VulnType.SSTI),
    (re.compile(r"Environment\s*\(.*from_string"), VulnType.SSTI),
    (re.compile(r"\.render\s*\(.*\{"), VulnType.SSTI),
    # Path manipulation — suspicious constructors, not necessarily LFI.
    # These build paths but don't do I/O. The actual vulnerability type
    # (DoS, path traversal, race condition) depends on how the constructed
    # path is used by callers. Classify as SUSPICIOUS so the LLM analyzes
    # freely rather than being pre-judged as LFI.
    (re.compile(r"posixpath\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"ntpath\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"os\.path\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"PurePosixPath"), VulnType.SUSPICIOUS),
    (re.compile(r"PureWindowsPath"), VulnType.SUSPICIOUS),
    (re.compile(r"pathlib\.PurePosixPath"), VulnType.SUSPICIOUS),
    (re.compile(r"zipfile\.Path"), VulnType.SUSPICIOUS),
    # Archive extraction — zip slip / tar slip → AFO (writes files)
    (re.compile(r"zipfile\.ZipFile"), VulnType.AFO),
    (re.compile(r"zipfile\.ZipFile\.extractall"), VulnType.AFO),
    (re.compile(r"zipfile\.ZipFile\.extract"), VulnType.AFO),
    (re.compile(r"tarfile\.open"), VulnType.AFO),
    (re.compile(r"tarfile\.extractall"), VulnType.AFO),
    # File write / copy via less common paths
    (re.compile(r"pathlib\.Path\(.*\)\.write"), VulnType.AFO),
    # File delete / remove operations
    (re.compile(r"os\.remove\s*\("), VulnType.AFO),
    (re.compile(r"os\.unlink\s*\("), VulnType.AFO),
    # File read via less common paths
    (re.compile(r"io\.open"), VulnType.LFI),
    # File read via method calls on Path/file objects
    (re.compile(r"\.read_text\s*\("), VulnType.LFI),
    (re.compile(r"\.read_bytes\s*\("), VulnType.LFI),
    # REDOS: regex operations (body-level detection catches cases not in EXACT_SINKS)
    (re.compile(r"re\.(match|search|findall|fullmatch|sub|compile|split)"), VulnType.REDOS),
    (re.compile(r"fnmatch\.(translate|filter)"), VulnType.REDOS),
    # Dynamic import / code generation (exact built-in compile(), NOT re.compile)
    (re.compile(r"__import__"), VulnType.RCE),
    (re.compile(r"\bcompile\("), VulnType.RCE),
    # Dynamic import — often used in deserialization gadgets
    (re.compile(r"importlib\.import_module\s*\("), VulnType.SUSPICIOUS),
    (re.compile(r"import_module\s*\("), VulnType.SUSPICIOUS),
    # RCE: eval/exec in function bodies (catches inline calls in route handlers)
    (re.compile(r"\beval\s*\("), VulnType.RCE),
    (re.compile(r"\bexec\s*\("), VulnType.RCE),
    (re.compile(r"os\.system\s*\("), VulnType.RCE),
    (re.compile(r"os\.popen\s*\("), VulnType.RCE),
    (re.compile(r"subprocess\.\w+\s*\("), VulnType.RCE),
    # RCE: pickle/cloudpickle deserialization in function bodies
    (re.compile(r"pickle\.loads?\s*\("), VulnType.RCE),
    (re.compile(r"cloudpickle\.loads?\s*\("), VulnType.RCE),
    # LFI: bare open() in function bodies
    (re.compile(r"\bopen\s*\("), VulnType.LFI),
    # SQLI: execute/executemany in function bodies
    (re.compile(r"\bexecute\b"), VulnType.SQLI),
    (re.compile(r"executemany\b"), VulnType.SQLI),
    # SSRF: requests/urllib in function bodies
    (re.compile(r"requests\.\w+\s*\("), VulnType.SSRF),
    (re.compile(r"urlopen\s*\("), VulnType.SSRF),
    (re.compile(r"httpx\.\w+\s*\("), VulnType.SSRF),
    # ML: trust_remote_code=True enables arbitrary code execution via HF hub
    (re.compile(r"trust_remote_code\s*=\s*True"), VulnType.RCE),
    # ML: PyTorch deserialization (torch.load without weights_only)
    (re.compile(r"torch\.load\s*\("), VulnType.RCE),
    (re.compile(r"torch\.hub\.load\s*\("), VulnType.RCE),
    # ML: joblib model deserialization
    (re.compile(r"joblib\.load\s*\("), VulnType.RCE),
    # ML: HuggingFace from_pretrained (any model/tokenizer/processor)
    (re.compile(r"from_pretrained\s*\("), VulnType.RCE),
    # ML: transformers pipeline
    (re.compile(r"transformers\.pipeline\s*\("), VulnType.RCE),
    # ML: ONNX runtime — loads and executes model binaries
    (re.compile(r"onnxruntime\.InferenceSession\s*\("), VulnType.RCE),
    # ML: safetensors file load — path traversal
    (re.compile(r"safetensors\.\w+\.load_file\s*\("), VulnType.AFO),
    (re.compile(r"safetensors\.\w+\.load\s*\("), VulnType.AFO),
    # msgpack deserialization — arbitrary object instantiation via ext_hook
    (re.compile(r"msgpack\.unpackb?\s*\("), VulnType.RCE),
    # ML: numpy load with allow_pickle
    (re.compile(r"numpy\.load\s*\("), VulnType.RCE),
    # ML: MLflow model loading
    (re.compile(r"mlflow\.\w+\.load_model\s*\("), VulnType.RCE),
    # ML: TF/Keras model loading — custom layers can execute code
    (re.compile(r"(?:tf|tensorflow|keras)\.\w*models?\.load_model\s*\("), VulnType.RCE),
    # -- LangGraph architecture-level vulnerabilities --
    # Msgpack ext_hook deserialization with importlib
    (re.compile(r"importlib\.import_module"), VulnType.LANGGRAPH),
    (re.compile(r"ormsgpack\.unpackb\s*\(.*ext_hook"), VulnType.LANGGRAPH),
    (re.compile(r"loads_typed\s*\(\s*[\"']msgpack[\"']"), VulnType.LANGGRAPH),
    (re.compile(r"dumps_typed\s*\(.*msgpack"), VulnType.LANGGRAPH),
    (re.compile(r"serialized_value_from_proto"), VulnType.LANGGRAPH),
    (re.compile(r"allowed_msgpack_modules\s*=\s*True"), VulnType.LANGGRAPH),
    # gRPC server registration (no-auth risk)
    (re.compile(r"Register(Admin|Assistants|Cache|Crons|Runs|Threads|Checkpointer)Server"), VulnType.LANGGRAPH),
    (re.compile(r"grpc\.NewServer\s*\("), VulnType.LANGGRAPH),
    # Template injection in headers/webhooks
    (re.compile(r"renderHeaderTemplate"), VulnType.LANGGRAPH),
    (re.compile(r"headerTemplateRe"), VulnType.LANGGRAPH),
    # Custom crypto
    (re.compile(r"NewAESEncryptor"), VulnType.LANGGRAPH),
    (re.compile(r"AESEncryptor\.Encrypt"), VulnType.LANGGRAPH),
    (re.compile(r"AESEncryptor\.Decrypt"), VulnType.LANGGRAPH),
    (re.compile(r"LANGGRAPH_AES_KEY"), VulnType.LANGGRAPH),
    # Dangerous admin
    (re.compile(r"adminServerImpl.*Truncate"), VulnType.LANGGRAPH),
    (re.compile(r"TruncateRequest"), VulnType.LANGGRAPH),
    # -- Java / JVM-wide sensitive patterns --
    # Java RCE: Runtime.exec and variants
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("), VulnType.RCE),
    (re.compile(r"Runtime\.getRuntime\b"), VulnType.RCE),
    (re.compile(r"new\s+ProcessBuilder\s*\("), VulnType.RCE),
    (re.compile(r"\.start\(\)"), VulnType.SUSPICIOUS),  # ProcessBuilder.start
    # Java: Script engine eval
    (re.compile(r"ScriptEngine(Manager)?\.\w+\s*\("), VulnType.RCE),
    (re.compile(r"\.eval\s*\("), VulnType.RCE),
    # Java: SpEL / expression / OGNL / MVEL eval
    (re.compile(r"SpelExpressionParser\."), VulnType.RCE),
    (re.compile(r"parseExpression\s*\("), VulnType.RCE),
    (re.compile(r"Ognl\.\w+\s*\("), VulnType.RCE),
    (re.compile(r"MVEL\.\w+\s*\("), VulnType.RCE),
    (re.compile(r"Jexl(Engine|Expression)"), VulnType.RCE),
    (re.compile(r"ELProcessor\.\w+\s*\("), VulnType.RCE),
    (re.compile(r"GroovyShell\.\w+\s*\("), VulnType.RCE),
    # Java: JNDI injection
    (re.compile(r"InitialContext\.lookup\s*\("), VulnType.RCE),
    (re.compile(r"Context\.lookup\s*\("), VulnType.RCE),
    # Java: Deserialization
    (re.compile(r"ObjectInputStream\.\w+Object\s*\("), VulnType.RCE),
    (re.compile(r"\.readObject\s*\("), VulnType.RCE),
    (re.compile(r"ObjectMapper\.enableDefaultTyping\s*\("), VulnType.RCE),
    (re.compile(r"Yaml\.load\s*\("), VulnType.RCE),
    (re.compile(r"XStream\.fromXML\s*\("), VulnType.RCE),
    (re.compile(r"SnakeYaml"), VulnType.RCE),
    (re.compile(r"new\s+ObjectInputStream\s*\("), VulnType.RCE),
    # Java: LFI / path traversal
    (re.compile(r"new\s+FileInputStream\s*\("), VulnType.LFI),
    (re.compile(r"new\s+FileReader\s*\("), VulnType.LFI),
    (re.compile(r"Files\.readString\s*\("), VulnType.LFI),
    (re.compile(r"Files\.readAllBytes\s*\("), VulnType.LFI),
    (re.compile(r"Files\.readAllLines\s*\("), VulnType.LFI),
    (re.compile(r"FileUtils\.readFileToString\s*\("), VulnType.LFI),
    (re.compile(r"FileUtils\.readLines\s*\("), VulnType.LFI),
    (re.compile(r"ResourceLoader\.getResource\s*\("), VulnType.LFI),
    (re.compile(r"ClassPathResource\s*\("), VulnType.LFI),
    (re.compile(r"Paths\.get\s*\("), VulnType.LFI),
    # Java: SSRF — outbound HTTP
    (re.compile(r"URL\.openConnection\s*\("), VulnType.SSRF),
    (re.compile(r"URL\.openStream\s*\("), VulnType.SSRF),
    (re.compile(r"CloseableHttpClient\.\w+\s*\("), VulnType.SSRF),
    (re.compile(r"OkHttpClient\.\w+\s*\("), VulnType.SSRF),
    (re.compile(r"RestTemplate\.\w+For\w+\s*\("), VulnType.SSRF),
    (re.compile(r"RestTemplate\.exchange\s*\("), VulnType.SSRF),
    (re.compile(r"WebClient\.create\s*\("), VulnType.SSRF),
    (re.compile(r"new\s+Socket\s*\("), VulnType.SSRF),
    (re.compile(r"new\s+URL\s*\("), VulnType.SSRF),
    # Java: SQLI
    (re.compile(r"Statement\.execute(Query|Update)?\s*\("), VulnType.SQLI),
    (re.compile(r"JdbcTemplate\.\w+\s*\("), VulnType.SQLI),
    (re.compile(r"Session\.create(Query|SQLQuery)\s*\("), VulnType.SQLI),
    (re.compile(r"EntityManager\.createNativeQuery\s*\("), VulnType.SQLI),
    (re.compile(r"SqlSessionTemplate\.\w+\s*\("), VulnType.SQLI),
    # Java: XXE
    (re.compile(r"DocumentBuilderFactory\.newInstance\s*\("), VulnType.XXE),
    (re.compile(r"DocumentBuilder\.parse\s*\("), VulnType.XXE),
    (re.compile(r"SAXParser\.parse\s*\("), VulnType.XXE),
    (re.compile(r"SAXReader\.read\s*\("), VulnType.XXE),
    (re.compile(r"SAXBuilder\.build\s*\("), VulnType.XXE),
    (re.compile(r"XMLReader\.parse\s*\("), VulnType.XXE),
    (re.compile(r"XMLInputFactory\.create\w+Reader\s*\("), VulnType.XXE),
    (re.compile(r"XmlMapper\s*\("), VulnType.XXE),
    # Java: AFO / file write
    (re.compile(r"new\s+FileOutputStream\s*\("), VulnType.AFO),
    (re.compile(r"new\s+FileWriter\s*\("), VulnType.AFO),
    (re.compile(r"Files\.write\s*\("), VulnType.AFO),
    (re.compile(r"Files\.copy\s*\("), VulnType.AFO),
    (re.compile(r"Files\.move\s*\("), VulnType.AFO),
    (re.compile(r"Files\.delete\s*\("), VulnType.AFO),
    (re.compile(r"FileUtils\.writeByteArrayToFile\s*\("), VulnType.AFO),
    # Java: SSTI (template engines)
    (re.compile(r"freemarker\.template\.Template\.process\s*\("), VulnType.SSTI),
    (re.compile(r"Velocity\.evaluate\s*\("), VulnType.SSTI),
    (re.compile(r"VelocityEngine\.evaluate\s*\("), VulnType.SSTI),
    (re.compile(r"TemplateEngine\.process\s*\("), VulnType.SSTI),
    (re.compile(r"PebbleEngine\.getTemplate\s*\("), VulnType.SSTI),
    # Java: XSS
    (re.compile(r"getWriter\(\)\.\w+\s*\("), VulnType.XSS),
    (re.compile(r"ModelAndView\.addObject\s*\("), VulnType.XSS),
    # Java: REDOS
    (re.compile(r"Pattern\.compile\s*\("), VulnType.REDOS),
    (re.compile(r"Pattern\.matches\s*\("), VulnType.REDOS),
    (re.compile(r"String\.matches\s*\("), VulnType.REDOS),
    (re.compile(r"String\.replaceAll\s*\("), VulnType.REDOS),
    (re.compile(r"String\.split\s*\("), VulnType.REDOS),
]

# ---------------------------------------------------------------------------
# Logic signal patterns — functions whose body patterns suggest logic
# vulnerabilities that don't involve a dangerous API sink.
# ---------------------------------------------------------------------------

LOGIC_SIGNAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Type confusion: user-supplied role/permission used in truthy check
    (re.compile(r"""\.get\(['"]role['"]\)"""), "type_confusion"),
    (re.compile(r"""\.get\(['"]permission['"]\)"""), "type_confusion"),
    # IDOR: user_id/data looked up by user-controlled ID without auth check
    (re.compile(r"""profiles\.get\(.*user_id"""), "idor"),
    (re.compile(r"""def .*(?:get_user|user_profile|get_profile)"""), "idor"),
    # TOCTOU: path validated then read/written in separate calls
    (re.compile(r"""\.resolve\(\).*[\s\S]{0,200}\.read_text\("""), "toctou"),
    (re.compile(r"""\.resolve\(\).*[\s\S]{0,200}\.remove\("""), "toctou"),
    # Permission override: parameter overrides instance-level permission
    (re.compile(r"""context_role|effective_role|override_role"""), "permission_override"),
    # State machine: payment/transaction processing without idempotency
    (re.compile(r"""class\s+\w*(?:Payment|Transaction|Order)\w*"""), "state_machine"),
    (re.compile(r"""def\s+(?:process_payment|refund|_charge_api|_refund_api)"""), "state_machine"),
]


def detect_logic_signal(source_code: str) -> str | None:
    """Detect logic vulnerability signals in function body source code.

    Returns the signal name string (e.g. ``"idor"``, ``"toctou"``) or
    ``None`` if no logic signal pattern matches.
    """
    for pattern, signal_name in LOGIC_SIGNAL_PATTERNS:
        if pattern.search(source_code):
            return signal_name
    return None


def classify_sensitive_body(source_code: str) -> VulnType | None:
    """Check a function's body source code for sensitive API calls.

    Returns the ``VulnType`` of the first matching pattern, or ``None``
    if no sensitive calls are found.

    This is used by ``TreeSitterPathFinder`` in its second pass to flag
    functions for Explore slots — catching logic-level vulnerabilities
    that don't have a telltale sink function name.
    """
    for pattern, vuln_type in SENSITIVE_CALL_PATTERNS:
        if pattern.search(source_code):
            return vuln_type
    return None
