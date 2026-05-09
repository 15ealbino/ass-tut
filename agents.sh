#!/usr/bin/env bash
# Launch a tmux session for monitoring Claude Code agent teams.
# Usage: ./agents.sh [session-name]

SESSION="${1:-agents}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Attach to existing session if it already exists
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Attaching to existing session: $SESSION"
  exec tmux attach-session -t "$SESSION"
fi

# ── Layout ────────────────────────────────────────────────────────────────────
#
#  Window 0 "main"  — full-width Claude Code shell (primary work / orchestrator)
#
#  Window 1 "agents" — 2×2 grid for watching up to 4 parallel agents
#   ┌──────────────┬──────────────┐
#   │  agent-1     │  agent-2     │
#   ├──────────────┼──────────────┤
#   │  agent-3     │  agent-4     │
#   └──────────────┴──────────────┘
#
#  Window 2 "logs"  — split: backend log | frontend log
#   ┌──────────────┬──────────────┐
#   │  backend     │  frontend    │
#   └──────────────┴──────────────┘
#
# ─────────────────────────────────────────────────────────────────────────────

tmux new-session  -d -s "$SESSION" -n "main"  -c "$DIR"

# ── Window 1: 2×2 agent grid ─────────────────────────────────────────────────
tmux new-window   -t "$SESSION" -n "agents" -c "$DIR"

# Split into 4 panes: top-left | top-right | bottom-left | bottom-right
tmux split-window -t "$SESSION:agents"   -h -c "$DIR"          # top-right
tmux split-window -t "$SESSION:agents.0" -v -c "$DIR"          # bottom-left
tmux split-window -t "$SESSION:agents.1" -v -c "$DIR"          # bottom-right

# Label each pane
tmux send-keys -t "$SESSION:agents.0" 'printf "\033]2;agent-1\033\\"' Enter
tmux send-keys -t "$SESSION:agents.1" 'printf "\033]2;agent-2\033\\"' Enter
tmux send-keys -t "$SESSION:agents.2" 'printf "\033]2;agent-3\033\\"' Enter
tmux send-keys -t "$SESSION:agents.3" 'printf "\033]2;agent-4\033\\"' Enter

# Even out the pane sizes
tmux select-layout -t "$SESSION:agents" tiled

# ── Window 2: backend + frontend logs ────────────────────────────────────────
tmux new-window   -t "$SESSION" -n "logs" -c "$DIR"
tmux split-window -t "$SESSION:logs" -h -c "$DIR/backend"

tmux send-keys -t "$SESSION:logs.0" \
  'echo "=== backend log ===" && cd '"$DIR/backend"'' Enter
tmux send-keys -t "$SESSION:logs.1" \
  'echo "=== frontend log ===" && cd '"$DIR/frontend"'' Enter

# ── Focus the main window ────────────────────────────────────────────────────
tmux select-window -t "$SESSION:main"
tmux send-keys -t "$SESSION:main" "cd $DIR && claude" Enter

echo "Session '$SESSION' created."
exec tmux attach-session -t "$SESSION"
