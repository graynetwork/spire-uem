#!/bin/sh
# Re-export every docs/diagrams/*.drawio to SVG for the README.
# Needs draw.io desktop on PATH (drawio); on a headless host it runs under xvfb-run.
# The export strips draw.io's embedded PNG copies of each label (they make every SVG
# ~800 KB) and pins a white background so the diagrams stay readable in dark mode.
set -eu
cd "$(dirname "$0")"

run() {
    if [ -n "${DISPLAY:-}" ] || ! command -v xvfb-run >/dev/null; then
        drawio "$@"
    else
        # The auth file lives here, not in /tmp, because the snap build of draw.io
        # has a private /tmp and cannot read xvfb-run's default auth file.
        xvfb-run -a -f "$PWD/.xvfb-auth" drawio "$@"
    fi
}

for f in *.drawio; do
    run -x -f svg --svg-theme light -o "${f%.drawio}.svg" "$f" --no-sandbox >/dev/null 2>&1
done
rm -f .xvfb-auth

python3 - <<'EOF'
import glob, re
for p in glob.glob("*.svg"):
    s = open(p).read()
    s = re.sub(r'<image [^>]*xlink:href="data:image/png;base64,[^"]*"[^>]*/>', "", s)
    s = re.sub(r'style="background: #ffffff;[^"]*"',
               'style="background: #ffffff; background-color: #ffffff; color-scheme: light;"', s, count=1)
    open(p, "w").write(s)
    print("exported", p)
EOF
