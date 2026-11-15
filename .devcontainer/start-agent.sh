#!/bin/sh
# Start (or restart) the Proof Gatekeeper agent inside the codespace.
WS=/workspaces/mame97-gk-agent
pkill -f "node $WS/server.js" 2>/dev/null; sleep 1
cd "$WS" || exit 1
GATEKEEPER_WASM="$WS/circuits/gatekeeper.wasm" \
GATEKEEPER_ZKEY="$WS/circuits/gatekeeper_final.zkey" \
PORT=8787 HOST=127.0.0.1 \
nohup node server.js > /tmp/agent.log 2>&1 &
echo "agent started, log: /tmp/agent.log"
