"""JavaScript/TypeScript-specific code pattern detection for attacker control verification."""

from __future__ import annotations

import os
from pathlib import Path

from agies.verification.language_patterns import LanguagePatterns


class JavaScriptPatterns(LanguagePatterns):
    """JavaScript/TypeScript pattern detection using path heuristics and content analysis."""

    TEST_PATTERNS = [
        "*.test.js",
        "*.test.ts",
        "*.test.jsx",
        "*.test.tsx",
        "*.spec.js",
        "*.spec.ts",
        "*.spec.jsx",
        "*.spec.tsx",
        "*/__tests__/**/*.js",
        "*/__tests__/**/*.ts",
        "*/__tests__/**/*.jsx",
        "*/__tests__/**/*.tsx",
        "*/test/**/*.js",
        "*/test/**/*.ts",
        "*/tests/**/*.js",
        "*/tests/**/*.ts",
    ]

    COMPILER_PATTERNS = [
        "webpack.config.js",
        "webpack.config.ts",
        "vite.config.js",
        "vite.config.ts",
        "rollup.config.js",
        "rollup.config.ts",
        "esbuild.config.js",
        "esbuild.config.ts",
        "next.config.js",
        "next.config.ts",
        "nuxt.config.js",
        "nuxt.config.ts",
        "tsconfig.json",
        "babel.config.js",
        "babel.config.ts",
        ".babelrc",
        "postcss.config.js",
        "tailwind.config.js",
        "tailwind.config.ts",
        "jest.config.js",
        "jest.config.ts",
        "karma.conf.js",
    ]

    STARTUP_PATTERNS = [
        "index.js",
        "index.ts",
        "app.js",
        "app.ts",
        "server.js",
        "server.ts",
        "main.js",
        "main.ts",
        "entry.js",
        "entry.ts",
        "*/bin/www",
        "*/bin/server",
        "cli.js",
        "cli.ts",
    ]

    def __init__(self, target_root: str) -> None:
        super().__init__(target_root)
        self._validation_fns: list[str] | None = None
        self._input_apis: list[str] | None = None
        self._entry_points: list[str] | None = None

    def is_test_code(self, path: str, content: str) -> bool:
        """Detect JS/TS test code by path and structure."""
        if self._path_matches(path, self.TEST_PATTERNS):
            return True

        # Check for test framework imports/globals
        test_indicators = [
            "describe(",
            "describe.skip(",
            "it(",
            "it.skip(",
            "test(",
            "test.skip(",
            "expect(",
            "beforeEach(",
            "afterEach(",
            "beforeAll(",
            "afterAll(",
            "import { describe",
            "import { it",
            "import { expect",
            "import { test",
            "import { jest",
            "import { vi",
            "import { beforeAll",
            "import { beforeEach",
            'from "jest"',
            'from "vitest"',
            'from "mocha"',
            'from "chai"',
            'from "@testing-library',
            'from "cypress"',
        ]
        for indicator in test_indicators:
            if indicator in content:
                return True

        return False

    def is_compiler_code(self, path: str, content: str) -> bool:
        """Detect build/bundler configuration code."""
        if self._path_matches(path, self.COMPILER_PATTERNS):
            return True

        build_indicators = [
            "module.exports =",
            "export default {",
            "__esModule",
            "require('webpack')",
            "require('vite')",
            "require('rollup')",
            "module.exports = {",
        ]
        # Only flag if it's clearly a config file (most of content is configuration)
        if path.endswith((".config.js", ".config.ts", ".config.mjs")):
            return True

        for indicator in build_indicators:
            if indicator in content:
                # Check if it's in a build config context
                if "config" in path.lower() or "build" in path.lower():
                    return True

        return False

    def is_startup_code(self, path: str, content: str) -> bool:
        """Detect JS/TS startup/entry point code."""
        if self._path_matches(path, self.STARTUP_PATTERNS):
            return True

        startup_indicators = [
            "app.listen(",
            "server.listen(",
            "http.createServer",
            "https.createServer",
            "app.run(",
            "process.on(",
            "module.exports = app",
            "export default app",
            "export default server",
            "ReactDOM.createRoot",
            "ReactDOM.render",
            "createApp(",
            "app.mount(",
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
        """Common JavaScript/TypeScript user input APIs."""
        if self._input_apis is None:
            self._input_apis = [
                # Express.js
                "req.query",
                "req.body",
                "req.params",
                "req.headers",
                "req.cookies",
                "req.signedCookies",
                "req.get(",
                "req.param(",
                # Next.js
                "params",
                "searchParams",
                "context.params",
                "context.query",
                # Koa.js
                "ctx.query",
                "ctx.request.query",
                "ctx.request.body",
                "ctx.params",
                "ctx.headers",
                # Fastify
                "request.query",
                "request.body",
                "request.params",
                "request.headers",
                # Node.js core
                "process.argv",
                "process.env",
                "process.stdin",
                # Standard APIs
                "URLSearchParams",
                "new URL(",
                "FormData",
                "new FormData(",
                # Web API (browser)
                "document.cookie",
                "localStorage.getItem",
                "sessionStorage.getItem",
                "window.location",
                "location.search",
                "location.hash",
                "location.href",
                # CLI
                "yargs.argv",
                "commander.args",
                "commander.opts",
                # GraphQL
                "args.",
                "root.",
                "context.",
                # File system
                "fs.readFileSync",
                "fs.readFile",
                "fs.createReadStream",
            ]
        return self._input_apis

    def get_external_entry_points(self) -> list[str]:
        """Common JavaScript/TypeScript external handler registration patterns."""
        if self._entry_points is None:
            self._entry_points = [
                # Express.js
                "app.get(",
                "app.post(",
                "app.put(",
                "app.delete(",
                "app.patch(",
                "app.all(",
                "app.use(",
                "app.route(",
                "router.get(",
                "router.post(",
                "router.put(",
                "router.delete(",
                "router.patch(",
                "router.all(",
                "router.use(",
                # Koa.js
                "router.get(",
                "router.post(",
                "router.put(",
                "router.delete(",
                # Fastify
                "fastify.get(",
                "fastify.post(",
                "fastify.put(",
                "fastify.delete(",
                "fastify.route(",
                # Next.js API routes
                "export async function GET",
                "export async function POST",
                "export async function PUT",
                "export async function DELETE",
                "export default async function handler",
                # WebSocket
                "new WebSocket(",
                "io.on(",
                "socket.on(",
                "ws.on(",
                # Message queues
                "channel.consume(",
                "channel.subscribe(",
                "mq.subscribe(",
                "pubsub.subscribe(",
                "kafka.subscribe(",
                # Cloud functions
                "exports.handler",
                "exports.handler =",
                "export const handler",
                "module.exports.handler",
                # Generic handlers
                "function handler(",
                "function handle(",
                "function onRequest(",
                "function onMessage(",
                # Next.js API route export
                "export default function handler",
                # Express middleware
                "app.error(",
                # GraphQL
                "graphqlHTTP(",
                "ApolloServer",
                # NestJS
                "@Controller",
                "@Get",
                "@Post",
                "@Put",
                "@Delete",
                "@Patch",
                "@All",
            ]
        return self._entry_points

    def get_validation_functions(self) -> list[str]:
        """Known JavaScript/TypeScript validation/sanitization function names."""
        if self._validation_fns is None:
            self._validation_fns = [
                # Express-validator
                "body(",
                "param(",
                "query(",
                "header(",
                "validationResult",
                "check(",
                "sanitize(",
                "sanitizeBody(",
                "sanitizeParam(",
                "sanitizeQuery(",
                # Joi
                "Joi.object(",
                "Joi.string(",
                "Joi.number(",
                "Joi.boolean(",
                "Joi.array(",
                "Joi.validate",
                "schema.validate",
                # Zod
                "z.object(",
                "z.string(",
                "z.number(",
                "z.boolean(",
                "z.array(",
                "z.enum(",
                "z.parse",
                "z.parseSafe",
                "schema.parse",
                # Yup
                "yup.object(",
                "yup.string(",
                "yup.number(",
                "yup.boolean(",
                "yup.array(",
                "yup.validate",
                # Class-validator (TypeScript)
                "class-validator",
                "@IsString",
                "@IsNumber",
                "@IsInt",
                "@IsBoolean",
                "@IsArray",
                "@IsEmail",
                "@IsEnum",
                "@IsOptional",
                "@IsDefined",
                "@Min",
                "@Max",
                "@Length",
                "@Matches",
                "@Validate",
                "@ValidateNested",
                "@IsIn",
                "@IsNotEmpty",
                "@IsObject",
                "validate(",
                "validateOrReject",
                # DOMPurify
                "DOMPurify.sanitize",
                "dompurify.sanitize",
                # Helmet (Express security headers)
                "helmet(",
                # HTML sanitization
                "sanitizeHtml",
                "stripHtml",
                "xss(",
                # Lodash security
                "_.escape",
                "_.unescape",
                # Native
                "encodeURI",
                "encodeURIComponent",
                "escape(",
                # Custom
                "sanitize",
                "sanitizeInput",
                "validateInput",
                "validateBody",
                "validateParams",
                "validateQuery",
                "validateRequest",
                "cleanInput",
                "purify",
                "filterInput",
                "stripXSS",
            ]
        return self._validation_fns
