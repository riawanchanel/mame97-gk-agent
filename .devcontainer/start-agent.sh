#!/bin/sh
# Start (or restart) the Proof Gatekeeper agent + its public tunnel inside the codespace.
WS=/workspaces/mame97-gk-agent
cd "$WS" || exit 1
pkill -f "node $WS/server.js" 2>/dev/null
pkill -f "cloudflared tunnel" 2>/dev/null
sleep 1
GATEKEEPER_WASM="$WS/circuits/gatekeeper.wasm" \
GATEKEEPER_ZKEY="$WS/circuits/gatekeeper_final.zkey" \
PORT=8787 HOST=127.0.0.1 \
nohup node server.js > /tmp/agent.log 2>&1 &
# cloudflared quick tunnel (codespace egress is direct, no proxy needed)
if [ ! -x "$HOME/bin/cloudflared" ]; then
  mkdir -p "$HOME/bin"
  curl -sL -o "$HOME/bin/cloudflared" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
  chmod +x "$HOME/bin/cloudflared"
fi
nohup "$HOME/bin/cloudflared" tunnel --no-autoupdate --url http://127.0.0.1:8787 > /tmp/tunnel.log 2>&1 &
# publish the current tunnel URL into the repo so the operator can read it
for i in $(seq 1 30); do
  URL=$(grep -o -E "https://[a-z0-9-]+\.trycloudflare\.com" /tmp/tunnel.log | grep -v "api.trycloudflare" | head -1)
  [ -n "$URL" ] && break
  sleep 2
done
if [ -n "$URL" ]; then
  echo "$URL" > "$WS/ENDPOINT_URL.txt"
  git add ENDPOINT_URL.txt >/dev/null 2>&1
  git -c user.email="riawanchanel@gmail.com" -c user.name="riawanchanel" commit -q -m "endpoint url update" >/dev/null 2>&1
  git push -q origin HEAD >/dev/null 2>&1
  echo "tunnel URL published: $URL"
else
  echo "WARN: tunnel URL not found in log yet"
fi
echo "agent + tunnel started"
