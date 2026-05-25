"""Cross-file symbol resolution: builds a SymbolTable from SourceFileIR list."""

from __future__ import annotations

import os

from agies.analyzer.models import SourceFileIR, SymbolTable


def _module_to_path(module: str, base_dir: str) -> str | None:
    """Convert a module name ('foo.bar') to a file path under base_dir.

    Checks: foo/bar.py, foo/bar/__init__.py, foo.py
    Returns None if not found.
    """
    # Try as file path
    parts = module.split(".")
    # foo/bar.py
    rel = os.path.join(*parts)
    candidate = os.path.join(base_dir, rel + ".py")
    if os.path.isfile(candidate):
        return os.path.normpath(candidate)
    # foo/bar/__init__.py
    candidate2 = os.path.join(base_dir, rel, "__init__.py")
    if os.path.isfile(candidate2):
        return os.path.normpath(candidate2)
    # foo.py (single-level)
    candidate3 = os.path.join(base_dir, parts[-1] + ".py")
    if os.path.isfile(candidate3):
        return os.path.normpath(candidate3)
    return None


class SymbolTableBuilder:
    """Build a SymbolTable from a list of parsed SourceFileIR objects."""

    def __init__(self, source_files: list[SourceFileIR]) -> None:
        self.source_files = source_files
        # Map file_path -> SourceFileIR for fast lookup
        self._file_map: dict[str, SourceFileIR] = {}
        # Map module name (e.g. "foo.bar") -> file_path
        self._module_file_map: dict[str, str] = {}
        # Base directory for relative import resolution
        self._base_dir: str = ""
        self.table = SymbolTable()

    def build(self) -> SymbolTable:
        """Run the full build and return the SymbolTable."""
        # Index files by path
        for sf in self.source_files:
            if sf.parse_error:
                continue
            self._file_map[sf.file_path] = sf
            self.table.files[sf.file_path] = sf

        # Determine base directory from common prefix of file paths
        if self._file_map:
            paths = list(self._file_map.keys())
            self._base_dir = os.path.commonpath(paths) if len(paths) > 1 else os.path.dirname(paths[0])

        # Build module -> file map
        self._build_module_map()

        # Index all functions and classes
        self._index_symbols()

        # Resolve imports
        self._resolve_imports()

        return self.table

    def _build_module_map(self) -> None:
        """Map Python module names to their file paths."""
        for file_path in self._file_map:
            fpath = file_path.replace(self._base_dir, "").lstrip("/")
            # Strip extension and convert path separators to dots
            if fpath.endswith(".py"):
                module = fpath[:-3].replace("/", ".").replace("\\", ".")
                # Handle __init__.py -> module points to parent
                if fpath.endswith("/__init__.py"):
                    module = fpath[:-12].replace("/", ".").replace("\\", ".")
                self._module_file_map[module] = file_path

    def _index_symbols(self) -> None:
        """Index all functions and classes by qualified name."""
        for sf in self.source_files:
            if sf.parse_error:
                continue
            for fn in sf.functions:
                self.table.functions.setdefault(fn.qualified_name, []).append(fn)
            for cls in sf.classes:
                self.table.classes.setdefault(cls.qualified_name, []).append(cls)

    def _resolve_imports(self) -> None:
        """Resolve imports for each source file (best effort)."""
        for sf in self.source_files:
            if sf.parse_error:
                continue
            for imp in sf.imports:
                if imp.is_from:
                    self._resolve_from_import(imp)
                else:
                    self._resolve_direct_import(imp)

    def _resolve_from_import(self, imp: ImportIR) -> None:
        """Resolve 'from module import name [as alias]'."""
        module_path = self._module_file_map.get(imp.module)
        if module_path is None:
            # Try relative import
            relative = self._resolve_relative_import(imp)
            if relative:
                return
            # Track unresolved
            for name, _alias in imp.names:
                self.table.unresolved_names.append((imp.file_path, name, imp.line))
            return

        module_sf = self._file_map.get(module_path)
        if module_sf is None:
            return

        for name, _alias in imp.names:
            # Look for a function with that name in the module's file
            qname = imp.module + "." + name
            if qname in self.table.functions:
                continue
            # If the module has the symbol at top-level, it will be indexed
            # by its qualified_name. Check alternatives:
            found = False
            for fn in module_sf.functions:
                if fn.qualified_name.endswith("." + name):
                    found = True
                    break
            if not found:
                self.table.unresolved_names.append((imp.file_path, name, imp.line))

    def _resolve_direct_import(self, imp: ImportIR) -> None:
        """Resolve 'import module [as alias]'."""
        module_path = self._module_file_map.get(imp.module)
        if module_path is None:
            for name, _alias in imp.names:
                self.table.unresolved_names.append((imp.file_path, name, imp.line))
            return

    def _resolve_relative_import(self, imp: ImportIR) -> bool:
        """Try to resolve a from-import as a relative import based on file location."""
        if not imp.file_path:
            return False
        file_dir = os.path.dirname(imp.file_path)
        candidate = os.path.join(file_dir, imp.module.replace(".", os.sep) + ".py")
        if os.path.isfile(candidate):
            norm = os.path.normpath(candidate)
            if norm in self._file_map:
                return True
        return False

    def resolve_call_target(self, name: str, caller_file: str, caller_scope: list[str]) -> str | None:
        """Try to resolve a call target name to a fully qualified name.

        Returns the qualified name or None if unresolved.
        """
        # 1. Direct qualified name
        if name in self.table.functions:
            return name

        # 2. Check if name is a module-level function in this file
        caller_dir = os.path.dirname(caller_file)
        for scope_name in reversed(caller_scope):
            qname = scope_name + "." + name
            if qname in self.table.functions:
                return qname

        # 3. Check if name is imported into the caller's file
        caller_sf = self._file_map.get(caller_file)
        if caller_sf:
            for imp in caller_sf.imports:
                for imp_name, imp_alias in imp.names:
                    if imp_alias == name or imp_name == name:
                        candidate = imp.module + "." + name if imp.is_from else imp.module
                        if candidate in self.table.functions:
                            return candidate
                        # Try without module prefix
                        if name in self.table.functions:
                            return name
                        # Try just the name from the imported module
                        if imp.is_from:
                            for fn in self.table.functions:
                                if fn == imp.module + "." + name:
                                    return fn

        return None
