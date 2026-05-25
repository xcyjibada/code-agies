"""Integration helpers: run route analysis and inject results into auditor context."""

from agies.analyzer.router import build_route_map, format_routes_for_prompt, format_routes_for_report


def run_route_analysis(target_dir: str) -> dict:
    """Run the full route analysis pipeline.

    Returns a dict with:
      - route_map: RouteMap object
      - prompt_context: formatted text for LLM system prompt
      - report_section: formatted text for final Markdown report
      - vulnerable_endpoints: list of endpoints without @PreAuthorize or public comment
    """
    route_map = build_route_map(target_dir)

    # Identify truly vulnerable endpoints
    vulnerable = [
        ep for ep in route_map.endpoints
        if not ep.has_pre_authorize
        and not ep.comment_says_public
        and not ep.deprecated
        and not ep.common_service_commented
    ]

    # Active CommonService usage
    active_cs = [ep for ep in route_map.endpoints
                 if ep.has_common_service and not ep.common_service_commented]

    return {
        "route_map": route_map,
        "prompt_context": format_routes_for_prompt(route_map),
        "report_section": format_routes_for_report(route_map),
        "vulnerable_endpoints": vulnerable,
        "active_common_service_endpoints": active_cs,
        "total_endpoints": len(route_map.endpoints),
        "total_frontend_calls": len(route_map.frontend_calls),
        "matched_routes": sum(1 for m in route_map.mappings if m.matched),
    }
