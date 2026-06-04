"""Merge layer — Phase D Step 3.

Deterministically arranges Intent Agent outputs by node index.
No LLM calls — pure positional sorting.
"""

from __future__ import annotations

from typing import Any

from agies.engine.v3.aggregator.models import IntentResult


class MergeLayer:
    """Deterministically merges parallel Intent Agent outputs.

    Takes N ``IntentResult`` lists from parallel Intent Agents and
    arranges them in the correct call-chain order.
    """

    @staticmethod
    def merge(
        results: list[IntentResult],
        order: list[str] | None = None,
    ) -> str:
        """Produce a pseudocode call chain string from Intent results.

        Parameters
        ----------
        results : list[IntentResult]
            Intent analysis results in the correct call-chain order.
        order : list[str] or None
            Optional function-name order hint. If None, uses result order.

        Returns
        -------
        str
            Formatted pseudocode chain.
        """
        if order:
            ordered = MergeLayer._order_by_hint(results, order)
        else:
            ordered = results

        blocks: list[str] = []
        for i, ir in enumerate(ordered):
            if ir.pass_through and ir.code:
                # Pass through raw source for dangerous functions
                blocks.append(
                    f"# ── [{i}] {ir.func_name} ({ir.file_path}) [DANGEROUS: pass_through] ──\n"
                    f"# Intent: {ir.intent}\n"
                    + (f"# Suspicious: {'; '.join(ir.suspicious)}\n" if ir.suspicious else "")
                    + ir.code
                )
            else:
                blocks.append(
                    f"# ── [{i}] {ir.func_name} ({ir.file_path}) [summary] ──\n"
                    f"# Intent: {ir.intent}\n"
                    f"# Inputs: {ir.inputs}\n"
                    f"# Outputs: {ir.outputs}\n"
                    f"# Key Logic: {ir.key_logic}\n"
                    + (f"# Suspicious: {'; '.join(ir.suspicious)}\n" if ir.suspicious else "")
                )

        return "\n".join(blocks)

    @staticmethod
    def _order_by_hint(
        results: list[IntentResult],
        order: list[str],
    ) -> list[IntentResult]:
        """Reorder results to match a given function name order.

        Falls back to original order for functions not in the hint.
        """
        name_map = {r.func_name: r for r in results}
        ordered: list[IntentResult] = []
        seen: set[str] = set()

        for name in order:
            if name in name_map and name not in seen:
                ordered.append(name_map[name])
                seen.add(name)

        for r in results:
            if r.func_name not in seen:
                ordered.append(r)
                seen.add(r.func_name)

        return ordered

    @staticmethod
    def check_coherence(
        chain: str,
        function_count: int,
    ) -> dict[str, Any]:
        """Quick coherence check without LLM.

        Checks:
        - All functions present in the output?
        - Non-empty intent/inputs/outputs for each?

        Returns a dict with issues found (if any).
        """
        blocks = chain.strip().split("\n\n")
        issues: list[str] = []

        if len(blocks) != function_count:
            issues.append(
                f"Expected {function_count} functions, got {len(blocks)}"
            )

        for block in blocks:
            lines = block.strip().split("\n")
            has_intent = any(l.startswith("  Intent:") for l in lines)
            has_key_logic = any(l.startswith("  Key Logic:") for l in lines)

            if not has_intent:
                first_line = lines[0] if lines else "(empty block)"
                issues.append(f"Missing intent in: {first_line}")
            if not has_key_logic:
                first_line = lines[0] if lines else "(empty block)"
                issues.append(f"Missing key_logic in: {first_line}")

        return {
            "coherent": len(issues) == 0,
            "issues": issues,
            "function_count": len(blocks),
        }
