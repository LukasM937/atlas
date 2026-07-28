#!/bin/sh
# Shared pre-commit hook: install as .git/hooks/pre-commit in both the code
# repo and ~/Atlas. Blocks the commit on any secret or PII pattern hit in
# staged content. See TODO.md 0.4.
set -e

if command -v gitleaks >/dev/null 2>&1; then
    gitleaks protect --staged --no-banner --redact
else
    echo "pre-commit: gitleaks not installed (brew install gitleaks) — skipping that check" >&2
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
STORE_PY="${ATLAS_STORE_PY:-$REPO_ROOT/atlas_mcp/store.py}"
if [ ! -f "$STORE_PY" ]; then
    # ~/Atlas (notes-only repo) has no code of its own; fall back to the code repo.
    STORE_PY="$HOME/Developer/Github/atlas/atlas_mcp/store.py"
fi
if [ -f "$STORE_PY" ]; then
    python3 - "$STORE_PY" <<'PYEOF'
import importlib.util
import subprocess
import sys

store_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("atlas_store_scan", store_path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

staged = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
    capture_output=True, text=True, check=True,
).stdout.splitlines()

# tests/ is exempt from this layer: the PII/secret-shaped strings there are
# synthetic examples used to test scan_pii itself, not real data. gitleaks
# (above) still scans them. Docs are NOT exempt — if a doc trips this, reword
# it rather than widen the exemption.
hit = False
for f in staged:
    if f.startswith("tests/"):
        continue
    try:
        with open(f, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        continue
    found = mod.scan_pii(text)
    if found:
        print(f"pre-commit: {f} contains {', '.join(found)} — refusing to commit", file=sys.stderr)
        hit = True

sys.exit(1 if hit else 0)
PYEOF
fi
