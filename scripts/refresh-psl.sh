#!/usr/bin/env bash
# Downloads the public suffix list, strips comments and blank lines, and
# punycodes each rule label, preserving the "*." and "!" rule prefixes.
# Input order is preserved so regenerated output diffs cleanly against the
# previous file when only the source list content changed.
set -euo pipefail

SOURCE_URL="https://publicsuffix.org/list/public_suffix_list.dat"
OUT_FILE="apifier/src/main/res/raw/public_suffix_list.dat"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_path="${repo_root}/${OUT_FILE}"
raw_file="$(mktemp)"
trap 'rm -f "${raw_file}"' EXIT

curl -fsSL "${SOURCE_URL}" -o "${raw_file}"

python3 - "${raw_file}" "${out_path}" <<'PY'
import sys

src, dst = sys.argv[1], sys.argv[2]

with open(src, encoding="utf-8") as f:
    lines = f.readlines()

out = []
for line in lines:
    rule = line.strip()
    if not rule or rule.startswith("//"):
        continue

    prefix = ""
    body = rule
    if body.startswith("!"):
        prefix = "!"
        body = body[1:]
    if body.startswith("*."):
        prefix += "*."
        body = body[2:]

    labels = body.split(".")
    punycoded = ".".join(label.encode("idna").decode("ascii") for label in labels)
    out.append(f"{prefix}{punycoded}")

with open(dst, "w", encoding="utf-8", newline="\n") as f:
    for rule in out:
        f.write(rule + "\n")
PY

echo "Wrote $(wc -l < "${out_path}") rules to ${OUT_FILE}"
