"""Run v3 pipeline and output reports/PoCs to pocs/ subfolder."""
import os, sys, logging, json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force rich terminal output
import rich.console
_orig_console_init = rich.console.Console.__init__
def _patched_console_init(self, *a, **kw):
    kw['force_terminal'] = True
    kw['color_system'] = 'truecolor'
    return _orig_console_init(self, *a, **kw)
rich.console.Console.__init__ = _patched_console_init

from agies.engine.v3.runner import run_v3_pipeline

# Redirect logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format='%(levelname)s:%(message)s')

# Run v3 pipeline
TARGET = "/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c"

print("\n=== Running v3 pipeline ===", flush=True)
run_v3_pipeline(
    target=TARGET,
    model="deepseek-chat",
    verbose=True,
)

print("\n=== v3 pipeline complete ===", flush=True)
