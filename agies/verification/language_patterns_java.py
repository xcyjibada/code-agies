"""Java-specific code pattern detection for attacker control verification."""

from __future__ import annotations

import os
import re
from pathlib import Path

from agies.verification.language_patterns import LanguagePatterns


class JavaPatterns(LanguagePatterns):
    """Java-specific pattern detection using path heuristics and content analysis."""

    TEST_PATTERNS = [
        "*/src/test/java/**/*.java",
        "*/src/test/*.java",
        "*Test.java",
        "*Tests.java",
        "*TestCase.java",
        "*/test/**/*.java",
    ]

    COMPILER_PATTERNS = [
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "*/pom.xml",
        "*/build.gradle",
        "settings.gradle",
        "settings.gradle.kts",
    ]

    STARTUP_PATTERNS = [
        "*Application.java",          # Spring Boot: XxxApplication.java
        "*Main.java",                  # Java main class
        "*/src/main/java/**/ServletInitializer.java",
    ]

    def __init__(self, target_root: str) -> None:
        super().__init__(target_root)
        self._validation_fns: list[str] | None = None
        self._input_apis: list[str] | None = None
        self._entry_points: list[str] | None = None

    def is_test_code(self, path: str, content: str) -> bool:
        """Detect Java test code by path and annotations."""
        if self._path_matches(path, self.TEST_PATTERNS):
            return True

        # Check for test annotations/imports in the file content
        test_indicators = [
            "@Test",
            "@org.junit.jupiter.api.Test",
            "import org.junit",
            "import org.testng",
            "import org.mockito",
            "@ParameterizedTest",
            "@ExtendWith",
            "@SpringBootTest",
            "@WebMvcTest",
            "@DataJpaTest",
            "extends TestCase",
        ]
        for indicator in test_indicators:
            if indicator in content:
                return True

        return False

    def is_compiler_code(self, path: str, content: str) -> bool:
        """Detect build/compile-time code in Java projects."""
        if self._path_matches(path, self.COMPILER_PATTERNS):
            return True

        # Maven/Gradle plugin code annotations
        build_indicators = [
            "@Mojo",
            "@Parameter(defaultValue",
            "abstract class AbstractMojo",
            "implements Plugin",
            "extends DefaultMojo",
        ]
        for indicator in build_indicators:
            if indicator in content:
                return True

        return False

    def is_startup_code(self, path: str, content: str) -> bool:
        """Detect Java startup/initialization code."""
        if self._path_matches(path, self.STARTUP_PATTERNS):
            return True

        # Common startup patterns
        startup_indicators = [
            "SpringApplication.run",
            "SpringApplicationBuilder",
            "public static void main(String[]",
            "implements CommandLineRunner",
            "implements ApplicationRunner",
            "@PostConstruct",
            "InitializingBean",
            "ApplicationListener",
            "implements ServletContainerInitializer",
            "WebApplicationInitializer",
        ]
        for indicator in startup_indicators:
            if indicator in content:
                return True

        return False

    def is_production_code(self, path: str, content: str) -> bool:
        if self.is_test_code(path, content) or self.is_compiler_code(path, content):
            return False
        return True

    def get_user_input_entry_points(self) -> list[str]:
        """Common Java user input APIs (Servlet, Spring, JAX-RS, etc.)."""
        if self._input_apis is None:
            self._input_apis = [
                # Servlet API
                "HttpServletRequest",
                "ServletRequest",
                "request.getParameter",
                "request.getQueryString",
                "request.getHeader",
                "request.getCookies",
                "request.getInputStream",
                "request.getReader",
                "request.getPart",
                "request.getParts",
                "getServletContext",
                # Spring MVC
                "@RequestParam",
                "@PathVariable",
                "@RequestBody",
                "@RequestHeader",
                "@CookieValue",
                "@RequestAttribute",
                "@ModelAttribute",
                "@RequestPart",
                "@MatrixVariable",
                # Spring WebFlux
                "ServerHttpRequest",
                "ServerWebExchange",
                "@RequestParam",
                # JAX-RS
                "@QueryParam",
                "@PathParam",
                "@HeaderParam",
                "@CookieParam",
                "@FormParam",
                "@MatrixParam",
                "@Context",
                # General
                "System.getenv",
                "System.getProperty",
                "System.console",
                "Scanner(System.in",
                "BufferedReader(System.in",
                "Console.readLine",
                "java.util.Scanner",
                # File upload
                "MultipartFile",
                "@RequestPart",
                "Part",
            ]
        return self._input_apis

    def get_external_entry_points(self) -> list[str]:
        """Common Java external handler registration patterns."""
        if self._entry_points is None:
            self._entry_points = [
                # Spring MVC annotations
                "@RequestMapping",
                "@GetMapping",
                "@PostMapping",
                "@PutMapping",
                "@DeleteMapping",
                "@PatchMapping",
                "@RestController",
                "@Controller",
                # JAX-RS
                "@GET",
                "@POST",
                "@PUT",
                "@DELETE",
                "@PATCH",
                "@Path",
                "@ApplicationPath",
                "@Provider",
                # Servlet
                "@WebServlet",
                "@WebFilter",
                "@WebListener",
                "extends HttpServlet",
                "implements Filter",
                "implements Servlet",
                # WebSocket
                "@ServerEndpoint",
                "implements WebSocketHandler",
                # Message queues
                "@JmsListener",
                "@RabbitListener",
                "@KafkaListener",
                "@StreamListener",
                "@EventListener",
                # Functional
                "implements MessageHandler",
                "implements ChannelInterceptor",
                # Spring Cloud Gateway
                "implements GatewayFilter",
                "implements GlobalFilter",
                # Scheduled tasks
                "@Scheduled",
            ]
        return self._entry_points

    def get_validation_functions(self) -> list[str]:
        """Known Java validation/sanitization function names."""
        if self._validation_fns is None:
            self._validation_fns = [
                # javax.validation / jakarta.validation
                "@Valid",
                "@Validated",
                "javax.validation",
                "jakarta.validation",
                "@NotNull",
                "@NotEmpty",
                "@NotBlank",
                "@Size",
                "@Min",
                "@Max",
                "@Email",
                "@Pattern",
                "@AssertTrue",
                # Spring validation
                "org.springframework.validation",
                "Errors",
                "BindingResult",
                "@Validated",
                "Validator",
                "validate",
                "validateObject",
                "ValidationUtils",
                "org.springframework.validation.Validator",
                # OWASP ESAPI
                "org.owasp.esapi",
                "ESAPI.validator",
                "Validator.getValidInput",
                "Validator.isValidInput",
                "Validator.getValidSafeHTML",
                "Encoder.encodeForHTML",
                "Encoder.encodeForJavaScript",
                "Encoder.encodeForSQL",
                "Encoder.encodeForLDAP",
                "Encoder.encodeForOS",
                "Encoder.encodeForCSS",
                "Encoder.encodeForXML",
                "Encoder.encodeForXPath",
                # Apache Commons
                "StringEscapeUtils",
                "org.apache.commons.lang3.StringEscapeUtils",
                "org.apache.commons.text.StringEscapeUtils",
                "org.apache.commons.validator",
                "GenericValidator",
                "UrlValidator",
                "EmailValidator",
                # Google Guava
                "com.google.common.html.HtmlEscapers",
                "com.google.common.net.UrlEscapers",
                "Preconditions.checkNotNull",
                "Preconditions.checkArgument",
                # Hibernate Validator
                "org.hibernate.validator",
                "ConstraintValidator",
                "constraints",
                # Spring Security
                "@PreAuthorize",
                "@PostAuthorize",
                "@Secured",
                "SecurityContextHolder",
                # Custom validation patterns
                "sanitize",
                "sanitizeInput",
                "cleanInput",
                "escapeHtml",
                "escapeSql",
                "filterInput",
                "stripXSS",
                "purify",
            ]
        return self._validation_fns
