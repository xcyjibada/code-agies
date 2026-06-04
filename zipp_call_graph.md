# ProgramGraph — zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c 调用图

**生成时间**: 2026-05-30
**项目**: /tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c
**引擎**: treesitter
**节点(函数)**: 114
**边(调用)**: 73
**文件**: 5

---

## conftest.py

| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |
|---|------|------|------|------|----------|------|
| 1 | `pytest_configure` | 5-6 | 0 | 1 | 0.0000 |  |
| 2 | `add_future_flags` | 9-13 | 1 | 0 | 0.0000 |  |

---

## tests/test_complexity.py

| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |
|---|------|------|------|------|----------|------|
| 1 | `test_implied_dirs_performance` | 21-30 | 0 | 0 | 0.0000 | regex_operation=0.00 |
| 2 | `make_zip_path` | 32-41 | 2 | 2 | 0.0000 | regex_operation=0.00 |
| 3 | `make_names` | 44-60 | 1 | 0 | 0.0000 | regex_operation=0.00 |
| 4 | `make_deep_paths` | 63-64 | 1 | 0 | 0.0000 | regex_operation=0.00 |
| 5 | `make_deep_path` | 67-68 | 0 | 0 | 0.0000 | regex_operation=0.00 |
| 6 | `test_baseline_regex_complexity` | 70-77 | 0 | 0 | 0.0000 | regex_operation=0.00 |
| 7 | `test_glob_depth` | 80-87 | 0 | 0 | 0.0000 | regex_operation=0.00 |
| 8 | `test_glob_width` | 90-97 | 0 | 1 | 0.0000 | regex_operation=0.00 |
| 9 | `test_glob_width_and_depth` | 100-107 | 0 | 1 | 0.0000 | regex_operation=0.00 |

---

## tests/test_path.py

| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |
|---|------|------|------|------|----------|------|
| 1 | `_make_link` | 20-21 | 1 | 0 | 0.1175 | serialization=0.24 |
| 2 | `build_alpharep_fixture` | 24-70 | 0 | 1 | 0.1175 | serialization=0.24 |
| 3 | `setUp` | 82-84 | 0 | 0 | 0.1175 | serialization=0.24 |
| 4 | `zipfile_ondisk` | 86-93 | 4 | 0 | 0.1175 | serialization=0.24 |
| 5 | `test_iterdir_and_types` | 96-109 | 0 | 0 | 0.1175 | serialization=0.24 |
| 6 | `test_is_file_missing` | 112-114 | 0 | 0 | 0.1175 | serialization=0.24 |
| 7 | `test_iterdir_on_file` | 117-121 | 0 | 0 | 0.1175 | serialization=0.24 |
| 8 | `test_subdir_is_dir` | 124-129 | 0 | 0 | 0.1175 | serialization=0.24 |
| 9 | `test_open` | 132-140 | 0 | 0 | 0.1175 | serialization=0.24 |
| 10 | `test_open_encoding_utf16` | 142-155 | 0 | 0 | 0.1175 | serialization=0.24 |
| 11 | `test_open_encoding_errors` | 157-180 | 0 | 0 | 0.1175 | serialization=0.24 |
| 12 | `test_encoding_warnings` | 187-196 | 0 | 0 | 0.1175 | serialization=0.24 |
| 13 | `test_open_write` | 198-207 | 0 | 0 | 0.1175 | serialization=0.24 |
| 14 | `test_open_extant_directory` | 210-216 | 0 | 0 | 0.1175 | serialization=0.24 |
| 15 | `test_open_binary_invalid_args` | 219-224 | 0 | 0 | 0.1175 | serialization=0.24 |
| 16 | `test_open_missing_directory` | 227-233 | 0 | 0 | 0.1175 | serialization=0.24 |
| 17 | `test_read` | 236-242 | 0 | 0 | 0.1175 | serialization=0.24 |
| 18 | `test_joinpath` | 245-250 | 0 | 0 | 0.1175 | serialization=0.24 |
| 19 | `test_joinpath_multiple` | 253-256 | 0 | 0 | 0.1175 | serialization=0.24 |
| 20 | `test_traverse_truediv` | 259-264 | 0 | 0 | 0.1175 | serialization=0.24 |
| 21 | `test_pathlike_construction` | 267-273 | 0 | 1 | 0.1175 | serialization=0.24 |
| 22 | `test_traverse_pathlike` | 276-278 | 0 | 0 | 0.1175 | serialization=0.24 |
| 23 | `test_parent` | 281-284 | 0 | 0 | 0.1175 | serialization=0.24 |
| 24 | `test_dir_parent` | 287-290 | 0 | 0 | 0.1175 | serialization=0.24 |
| 25 | `test_missing_dir_parent` | 293-295 | 0 | 0 | 0.1175 | serialization=0.24 |
| 26 | `test_mutability` | 298-310 | 0 | 0 | 0.1175 | serialization=0.24 |
| 27 | `huge_zipfile` | 314-321 | 1 | 0 | 0.1175 | serialization=0.24 |
| 28 | `test_joinpath_constant_time` | 323-332 | 0 | 1 | 0.1175 | serialization=0.24 |
| 29 | `test_read_does_not_close` | 335-339 | 0 | 1 | 0.1175 | serialization=0.24 |
| 30 | `test_subclass` | 342-347 | 0 | 0 | 0.1175 | serialization=0.24 |
| 31 | `test_filename` | 350-352 | 0 | 0 | 0.1175 | serialization=0.24 |
| 32 | `test_root_name` | 355-360 | 0 | 0 | 0.1175 | serialization=0.24 |
| 33 | `test_suffix` | 363-379 | 0 | 0 | 0.1175 | serialization=0.24 |
| 34 | `test_suffixes` | 382-401 | 0 | 0 | 0.1175 | serialization=0.24 |
| 35 | `test_suffix_no_filename` | 404-408 | 0 | 0 | 0.1175 | serialization=0.24 |
| 36 | `test_stem` | 411-427 | 0 | 0 | 0.1175 | serialization=0.24 |
| 37 | `test_root_parent` | 430-434 | 0 | 0 | 0.1175 | serialization=0.24 |
| 38 | `test_root_unnamed` | 437-452 | 0 | 0 | 0.1175 | serialization=0.24 |
| 39 | `test_match_and_glob` | 455-463 | 0 | 0 | 0.1175 | serialization=0.24 |
| 40 | `test_glob_recursive` | 466-471 | 0 | 0 | 0.1175 | serialization=0.24 |
| 41 | `test_glob_dirs` | 474-477 | 0 | 0 | 0.1175 | serialization=0.24 |
| 42 | `test_glob_subdir` | 480-483 | 0 | 0 | 0.1175 | serialization=0.24 |
| 43 | `test_glob_subdirs` | 486-490 | 0 | 0 | 0.1175 | serialization=0.24 |
| 44 | `test_glob_does_not_overmatch_dot` | 493-496 | 0 | 0 | 0.1175 | serialization=0.24 |
| 45 | `test_glob_single_char` | 499-504 | 0 | 0 | 0.1175 | serialization=0.24 |
| 46 | `test_glob_chars` | 507-513 | 0 | 0 | 0.1175 | serialization=0.24 |
| 47 | `test_glob_empty` | 515-518 | 0 | 0 | 0.1175 | serialization=0.24 |
| 48 | `test_eq_hash` | 521-529 | 0 | 0 | 0.1175 | serialization=0.24 |
| 49 | `test_is_symlink` | 532-535 | 0 | 0 | 0.1175 | serialization=0.24 |
| 50 | `test_relative_to` | 538-544 | 0 | 0 | 0.1175 | serialization=0.24 |
| 51 | `test_inheritance` | 547-550 | 0 | 0 | 0.1175 | serialization=0.24 |
| 52 | `test_pickle` | 560-566 | 0 | 1 | 0.1175 | serialization=0.24 |
| 53 | `test_extract_orig_with_implied_dirs` | 569-577 | 0 | 1 | 0.1175 | serialization=0.24 |
| 54 | `test_getinfo_missing` | 580-586 | 0 | 0 | 0.1175 | serialization=0.24 |
| 55 | `test_malformed_paths` | 588-604 | 0 | 0 | 0.1175 | serialization=0.24 |
| 56 | `test_unsupported_names` | 606-623 | 0 | 0 | 0.1175 | serialization=0.24 |
| 57 | `test_backslash_not_separator` | 625-636 | 0 | 1 | 0.1175 | serialization=0.24 |
| 58 | `test_interface` | 639-643 | 0 | 0 | 0.1175 | serialization=0.24 |
| 59 | `__init__` | 651-653 | 1 | 1 | 0.1175 | serialization=0.24 |
| 60 | `for_name` | 656-670 | 1 | 0 | 0.1175 | serialization=0.24 |

---

## zipp/__init__.py

| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |
|---|------|------|------|------|----------|------|
| 1 | `_parents` | 29-45 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 2 | `_ancestry` | 48-72 | 1 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 3 | `_difference` | 79-84 | 1 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 4 | `__getstate__` | 96-97 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 5 | `__setstate__` | 99-101 | 0 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 6 | `_implied_dirs` | 116-119 | 3 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 7 | `resolve_dir` | 128-136 | 1 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 8 | `getinfo` | 138-147 | 2 | 3 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 9 | `make` | 150-166 | 2 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 10 | `inject` | 169-176 | 0 | 3 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 11 | `namelist` | 185-186 | 16 | 6 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 12 | `_namelist` | 189-190 | 0 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 13 | `_name_set` | 192-193 | 8 | 4 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 14 | `_name_set_prop` | 196-197 | 0 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 15 | `_extract_text_encoding` | 200-204 | 2 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 16 | `__init__` | 312-323 | 6 | 6 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 17 | `__eq__` | 325-332 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 18 | `__hash__` | 334-335 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 19 | `open` | 337-355 | 3 | 4 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 20 | `_base` | 357-358 | 4 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 21 | `name` | 361-362 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 22 | `suffix` | 365-366 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 23 | `suffixes` | 369-370 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 24 | `stem` | 373-374 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 25 | `filename` | 377-378 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 26 | `read_text` | 380-383 | 0 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 27 | `read_bytes` | 385-387 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 28 | `_is_child` | 389-390 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 29 | `_next` | 392-393 | 2 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 30 | `is_dir` | 395-396 | 3 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 31 | `is_file` | 398-399 | 0 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 32 | `exists` | 401-402 | 2 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 33 | `iterdir` | 404-408 | 0 | 3 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 34 | `match` | 410-411 | 1 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 35 | `is_symlink` | 413-419 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 36 | `glob` | 421-428 | 1 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 37 | `rglob` | 430-431 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 38 | `relative_to` | 433-434 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 39 | `__str__` | 436-437 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 40 | `__repr__` | 439-440 | 0 | 0 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 41 | `joinpath` | 442-444 | 2 | 2 | 0.1941 | file_io=0.19, regex_operation=0.19 |
| 42 | `parent` | 449-455 | 0 | 1 | 0.1941 | file_io=0.19, regex_operation=0.19 |

---

## zipp/compat/overlay.py

| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |
|---|------|------|------|------|----------|------|
| 1 | `__hash__` | 29-30 | 0 | 0 | 0.0000 |  |

---

## 调用边

| # | Caller (file) | → | Callee (file) |
|---|--------------|---|--------------|
| 1 | `pytest_configure` (conftest.py) | → | `add_future_flags` (conftest.py) |
| 2 | `make_zip_path` (tests/test_complexity.py) | → | `make_deep_paths` (tests/test_complexity.py) |
| 3 | `make_zip_path` (tests/test_complexity.py) | → | `make_names` (tests/test_complexity.py) |
| 4 | `test_glob_width` (tests/test_complexity.py) | → | `make_zip_path` (tests/test_complexity.py) |
| 5 | `test_glob_width_and_depth` (tests/test_complexity.py) | → | `make_zip_path` (tests/test_complexity.py) |
| 6 | `__init__` (tests/test_path.py) | → | `__init__` (tests/test_path.py) |
| 7 | `build_alpharep_fixture` (tests/test_path.py) | → | `_make_link` (tests/test_path.py) |
| 8 | `test_backslash_not_separator` (tests/test_path.py) | → | `for_name` (tests/test_path.py) |
| 9 | `test_extract_orig_with_implied_dirs` (tests/test_path.py) | → | `zipfile_ondisk` (tests/test_path.py) |
| 10 | `test_joinpath_constant_time` (tests/test_path.py) | → | `huge_zipfile` (tests/test_path.py) |
| 11 | `test_pathlike_construction` (tests/test_path.py) | → | `zipfile_ondisk` (tests/test_path.py) |
| 12 | `test_pickle` (tests/test_path.py) | → | `zipfile_ondisk` (tests/test_path.py) |
| 13 | `test_read_does_not_close` (tests/test_path.py) | → | `zipfile_ondisk` (tests/test_path.py) |
| 14 | `__init__` (zipp/__init__.py) | → | `__init__` (zipp/__init__.py) |
| 15 | `__init__` (zipp/__init__.py) | → | `make` (zipp/__init__.py) |
| 16 | `__setstate__` (zipp/__init__.py) | → | `__init__` (zipp/__init__.py) |
| 17 | `_implied_dirs` (zipp/__init__.py) | → | `_difference` (zipp/__init__.py) |
| 18 | `_name_set` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 19 | `_name_set_prop` (zipp/__init__.py) | → | `_name_set` (zipp/__init__.py) |
| 20 | `_namelist` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 21 | `_parents` (zipp/__init__.py) | → | `_ancestry` (zipp/__init__.py) |
| 22 | `exists` (zipp/__init__.py) | → | `_name_set` (zipp/__init__.py) |
| 23 | `filename` (zipp/__init__.py) | → | `joinpath` (zipp/__init__.py) |
| 24 | `getinfo` (zipp/__init__.py) | → | `_name_set` (zipp/__init__.py) |
| 25 | `getinfo` (zipp/__init__.py) | → | `getinfo` (zipp/__init__.py) |
| 26 | `glob` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 27 | `inject` (zipp/__init__.py) | → | `_implied_dirs` (zipp/__init__.py) |
| 28 | `inject` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 29 | `is_file` (zipp/__init__.py) | → | `exists` (zipp/__init__.py) |
| 30 | `is_file` (zipp/__init__.py) | → | `is_dir` (zipp/__init__.py) |
| 31 | `is_symlink` (zipp/__init__.py) | → | `getinfo` (zipp/__init__.py) |
| 32 | `iterdir` (zipp/__init__.py) | → | `is_dir` (zipp/__init__.py) |
| 33 | `iterdir` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 34 | `joinpath` (zipp/__init__.py) | → | `_next` (zipp/__init__.py) |
| 35 | `joinpath` (zipp/__init__.py) | → | `resolve_dir` (zipp/__init__.py) |
| 36 | `match` (zipp/__init__.py) | → | `match` (zipp/__init__.py) |
| 37 | `name` (zipp/__init__.py) | → | `_base` (zipp/__init__.py) |
| 38 | `namelist` (zipp/__init__.py) | → | `_implied_dirs` (zipp/__init__.py) |
| 39 | `namelist` (zipp/__init__.py) | → | `namelist` (zipp/__init__.py) |
| 40 | `open` (zipp/__init__.py) | → | `_extract_text_encoding` (zipp/__init__.py) |
| 41 | `open` (zipp/__init__.py) | → | `exists` (zipp/__init__.py) |
| 42 | `open` (zipp/__init__.py) | → | `is_dir` (zipp/__init__.py) |
| 43 | `open` (zipp/__init__.py) | → | `open` (zipp/__init__.py) |
| 44 | `parent` (zipp/__init__.py) | → | `_next` (zipp/__init__.py) |
| 45 | `read_bytes` (zipp/__init__.py) | → | `open` (zipp/__init__.py) |
| 46 | `read_text` (zipp/__init__.py) | → | `_extract_text_encoding` (zipp/__init__.py) |
| 47 | `read_text` (zipp/__init__.py) | → | `open` (zipp/__init__.py) |
| 48 | `relative_to` (zipp/__init__.py) | → | `joinpath` (zipp/__init__.py) |
| 49 | `resolve_dir` (zipp/__init__.py) | → | `_name_set` (zipp/__init__.py) |
| 50 | `rglob` (zipp/__init__.py) | → | `glob` (zipp/__init__.py) |
| 51 | `stem` (zipp/__init__.py) | → | `_base` (zipp/__init__.py) |
| 52 | `suffix` (zipp/__init__.py) | → | `_base` (zipp/__init__.py) |
| 53 | `suffixes` (zipp/__init__.py) | → | `_base` (zipp/__init__.py) |

---

## 调用图统计

### 被调用最多的函数（入度 top-15）

| 函数 | 被调用次数 |
|------|-----------|
| `namelist` | 16 |
| `_name_set` | 8 |
| `_base` | 4 |
| `zipfile_ondisk` | 4 |
| `_implied_dirs` | 3 |
| `open` | 3 |
| `is_dir` | 3 |
| `getinfo` | 2 |
| `make` | 2 |
| `_extract_text_encoding` | 2 |
| `_next` | 2 |
| `exists` | 2 |
| `joinpath` | 2 |
| `make_zip_path` | 2 |
| `add_future_flags` | 1 |

### 调用最多的函数（出度 top-15）

| 函数 | 调用次数 |
|------|---------|
| `namelist` | 6 |
| `_name_set` | 4 |
| `open` | 4 |
| `getinfo` | 3 |
| `inject` | 3 |
| `iterdir` | 3 |
| `__setstate__` | 2 |
| `resolve_dir` | 2 |
| `_namelist` | 2 |
| `_name_set_prop` | 2 |
| `read_text` | 2 |
| `is_file` | 2 |
| `exists` | 2 |
| `glob` | 2 |
| `joinpath` | 2 |

### 跨文件调用边

_无跨文件调用（tree-sitter 不解析跨文件引用，CodeQL 可补全）_
