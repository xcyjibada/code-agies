{
  "target": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider",
  "timestamp": "2026-06-26T08:30:24.921731",
  "context": {
    "languages": [
      "Python"
    ],
    "file_count": 66
  },
  "static_findings": [],
  "priority_files": [
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/cleartokens.py",
      "score": 90,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/contrib/rest_framework/permissions.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *permission*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/__init__.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *command*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/createapplication.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *command*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0006_alter_application_client_secret.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *secret*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0008_alter_accesstoken_token.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0009_add_hash_client_secret.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *secret*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0011_refreshtoken_token_family.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0012_add_token_checksum.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/oauth2_validators.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *validator*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/validators.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *validator*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/views/token.py",
      "score": 70,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/templates/oauth2_provider/authorized-token-delete.html",
      "score": 60,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/templates/oauth2_provider/authorized-tokens.html",
      "score": 60,
      "reason": "matches *auth*; matches *oauth*; matches *token*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/__init__.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/admin.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/apps.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/backends.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/checks.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    },
    {
      "path": "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/compat.py",
      "score": 50,
      "reason": "matches *auth*; matches *oauth*"
    }
  ],
  "suggested_llm_targets": [
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/cleartokens.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/contrib/rest_framework/permissions.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/__init__.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/management/commands/createapplication.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0006_alter_application_client_secret.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0008_alter_accesstoken_token.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0009_add_hash_client_secret.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0011_refreshtoken_token_family.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/migrations/0012_add_token_checksum.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/oauth2_validators.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/validators.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/views/token.py",
    "/home/xcy/.local/lib/python3.14/site-packages/oauth2_provider/templates/oauth2_provider/authorized-token-delete.html"
  ],
  "scan_summary": "**Priority Scan Summary:**\n- Total files: 66\n- Phase 1 (deep): 13 high-value files, 1 chunk(s)\n- Phase 2 (coverage): 53 remaining files, 2 chunk(s)\n\n**Top Priority Files:**\n- [90] management/commands/cleartokens.py — matches *auth*; matches *oauth*; matches *token*\n- [70] contrib/rest_framework/permissions.py — matches *auth*; matches *oauth*; matches *permission*\n- [70] management/commands/__init__.py — matches *auth*; matches *oauth*; matches *command*\n- [70] management/commands/createapplication.py — matches *auth*; matches *oauth*; matches *command*\n- [70] migrations/0006_alter_application_client_secret.py — matches *auth*; matches *oauth*; matches *secret*"
}