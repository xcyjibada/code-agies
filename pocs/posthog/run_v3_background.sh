#!/usr/bin/env bash
# Usage: bash pocs/posthog/run_v3_background.sh
# This script starts the v3 pipeline in a tmux session.
# You can safely close the terminal window after it starts.
# Reattach later with: tmux attach -t agies-v3-posthog

set -e

SESSION="agies-v3-posthog"
TARGET="/tmp/posthog-master"
LOG="$PWD/pocs/posthog/v3_pipeline.log"

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null || true

echo "=== Starting v3 pipeline on PostHog in tmux session '$SESSION' ==="
echo "Target: $TARGET"
echo "Log:    $LOG"
echo ""
echo "Commands:"
echo "  Reattach:  tmux attach -t $SESSION"
echo "  Detach:    Ctrl+B, then D"
echo "  Kill:      tmux kill-session -t $SESSION"
echo "  Tail log:  tail -f $LOG"
echo ""

tmux new-session -d -s "$SESSION" -x 160 -y 50 "
  cd /home/xcy/workSpace/code-agies && \
  echo '[+] Started at \$(date)' && \
  PYTHONUNBUFFERED=1 python3 -u -m agies.engine.v3.runner \
    '$TARGET' \
    --model deepseek-chat \
    --verbose \
    2>&1 | tee '$LOG'
"

sleep 1
echo "=== Session started. Detaching. ==="
echo "You can close this terminal window now — the pipeline keeps running."
echo "Reattach later: tmux attach -t $SESSION"
