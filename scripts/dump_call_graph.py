#!/usr/bin/env python3
"""Dump a ProgramGraph as a markdown call-graph report.

Usage::

    # Tree-sitter (default)
    python3 scripts/dump_call_graph.py /path/to/project -o report.md

    # CodeQL (when available)
    python3 scripts/dump_call_graph.py /path/to/project --codeql -o report.md
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import date

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")


def dump_program_graph(
    project_path: str,
    engine: str = "treesitter",
) -> str:
    """Build a ProgramGraph and return a markdown report."""
    if engine == "codeql":
        from agies.engine.graph.codeql import CodeQLGraphGenerator

        if not CodeQLGraphGenerator.check_available():
            print(
                "CodeQL CLI not found. Install with:\n"
                "  python3 -c \"from agies.engine.graph.codeql import "
                "CodeQLGraphGenerator; CodeQLGraphGenerator.ensure_installed()\"",
                file=sys.stderr,
            )
            sys.exit(1)
        gen = CodeQLGraphGenerator()
    else:
        from agies.engine.graph.treesitter import TreeSitterGraphGenerator

        gen = TreeSitterGraphGenerator()

    pg = gen.build_program_graph(project_path)

    # ---- Build markdown ----
    lines: list[str] = []
    lines.append(f"# ProgramGraph — {os.path.basename(project_path)} 调用图")
    lines.append("")
    lines.append(f"**生成时间**: {date.today()}")
    lines.append(f"**项目**: {project_path}")
    lines.append(f"**引擎**: {engine}")
    lines.append(f"**节点(函数)**: {pg.total_nodes}")
    lines.append(f"**边(调用)**: {pg.total_edges}")
    lines.append(f"**文件**: {len(pg.file_nodes)}")
    lines.append("")

    # ---- By file ----
    for file_path, node_ids in sorted(pg.file_nodes.items()):
        rel_path = os.path.relpath(file_path, project_path)
        lines.append(f"---")
        lines.append("")
        lines.append(f"## {rel_path}")
        lines.append("")
        lines.append("| # | 函数 | 行号 | 入度 | 出度 | PageRank | 信号 |")
        lines.append("|---|------|------|------|------|----------|------|")

        # Deduplicate by node id (tree-sitter can double-match some functions)
        seen_nids: set[str] = set()
        unique_nodes: list = []
        for nid in node_ids:
            if nid not in seen_nids:
                seen_nids.add(nid)
                unique_nodes.append(pg.nodes[nid])
        nodes_in_file = sorted(unique_nodes, key=lambda n: n.line_start)
        for i, node in enumerate(nodes_in_file, 1):
            in_deg = len(pg.get_callers(node.id))
            out_deg = len(pg.get_callees(node.id))
            pr = node.pagerank_score
            sig_str = ", ".join(
                f"{k}={v:.2f}" for k, v in sorted(node.signals.items())
            )
            lines.append(
                f"| {i} | `{node.name}` "
                f"| {node.line_start}-{node.line_end} "
                f"| {in_deg} | {out_deg} "
                f"| {pr:.4f} "
                f"| {sig_str} |"
            )
        lines.append("")

    # ---- Edges ----
    lines.append("---")
    lines.append("")
    lines.append("## 调用边")
    lines.append("")
    lines.append("| # | Caller (file) | → | Callee (file) |")
    lines.append("|---|--------------|---|--------------|")

    # Build sorted edge list: by caller file then caller name
    edge_list: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for caller_id, callees in pg._forward.items():
        caller_node = pg.nodes.get(caller_id)
        if not caller_node:
            continue
        for callee_id in callees:
            key = (caller_id, callee_id)
            if key in seen:
                continue
            seen.add(key)
            callee_node = pg.nodes.get(callee_id)
            if not callee_node:
                continue
            edge_list.append((caller_id, callee_id))

    edge_list.sort(
        key=lambda x: (
            pg.nodes[x[0]].file_path,
            pg.nodes[x[0]].name,
            pg.nodes[x[1]].name,
        )
    )

    for i, (cid, clid) in enumerate(edge_list, 1):
        cn = pg.nodes[cid]
        cln = pg.nodes[clid]
        cfile = os.path.relpath(cn.file_path, project_path)
        clfile = os.path.relpath(cln.file_path, project_path)
        lines.append(
            f"| {i} | `{cn.name}` ({cfile}) "
            f"| → | "
            f"`{cln.name}` ({clfile}) |"
        )
    lines.append("")

    # ---- Stats ----
    lines.append("---")
    lines.append("")
    lines.append("## 调用图统计")
    lines.append("")

    # In-degree top
    in_deg_map: dict[str, int] = {}
    for nid, node in pg.nodes.items():
        in_deg_map[node.name] = len(pg.get_callers(nid))
    sorted_in = sorted(in_deg_map.items(), key=lambda x: -x[1])[:15]
    lines.append("### 被调用最多的函数（入度 top-15）")
    lines.append("")
    lines.append("| 函数 | 被调用次数 |")
    lines.append("|------|-----------|")
    for name, cnt in sorted_in:
        if cnt > 0:
            lines.append(f"| `{name}` | {cnt} |")
    lines.append("")

    # Out-degree top
    out_deg_map: dict[str, int] = {}
    for nid, node in pg.nodes.items():
        out_deg_map[node.name] = len(pg.get_callees(nid))
    sorted_out = sorted(out_deg_map.items(), key=lambda x: -x[1])[:15]
    lines.append("### 调用最多的函数（出度 top-15）")
    lines.append("")
    lines.append("| 函数 | 调用次数 |")
    lines.append("|------|---------|")
    for name, cnt in sorted_out:
        if cnt > 0:
            lines.append(f"| `{name}` | {cnt} |")
    lines.append("")

    # Cross-file edges
    cross_file: list[tuple[str, str]] = []
    for cid, clid in edge_list:
        cn = pg.nodes[cid]
        cln = pg.nodes[clid]
        if cn.file_path != cln.file_path:
            cross_file.append((cn.name, cln.name))

    lines.append("### 跨文件调用边")
    lines.append("")
    if cross_file:
        lines.append("| Caller | → | Callee |")
        lines.append("|--------|---|--------|")
        for caller, callee in cross_file:
            lines.append(f"| `{caller}` | → | `{callee}` |")
    else:
        lines.append("_无跨文件调用（tree-sitter 不解析跨文件引用，CodeQL 可补全）_")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dump call graph as markdown")
    parser.add_argument("project_path", help="Path to project source")
    parser.add_argument("-o", "--output", default="", help="Output file path")
    parser.add_argument(
        "--codeql",
        action="store_true",
        help="Use CodeQL engine (requires codeql CLI)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.project_path):
        print(f"Error: not a directory: {args.project_path}", file=sys.stderr)
        sys.exit(1)

    markdown = dump_program_graph(args.project_path, engine="codeql" if args.codeql else "treesitter")

    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown)
        print(f"Written to {args.output}")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
