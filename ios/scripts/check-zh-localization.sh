#!/bin/bash

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [catalog]" >&2
  exit 2
fi

catalog=${1:-"$script_dir/../HIbiki/Localizable.xcstrings"}

if ! jq empty "$catalog"; then
  echo "Invalid string catalog: $catalog" >&2
  exit 1
fi

# Follow Termind's Chinese spacing rules, including nested plural variations.
for language in zh-Hans zh-Hant; do
  violations=$(jq -r --arg language "$language" '
    .strings | to_entries[] as $entry
    | select($entry.value.shouldTranslate != false)
    | ($entry.value.localizations[$language] // {})
    | .. | objects | .stringUnit?.value? // empty
    | select(
        test("\\p{Han}")
        and (
          test("\\p{Han}[ \\t]+[A-Za-z0-9%@`]|[A-Za-z0-9%@`][ \\t]+\\p{Han}")
          or test("[ \\t]+[—·→：，。！？；、/:]|[—·→：，。！？；、/:][ \\t]+")
          or test("\\p{Han}[,.!?;]|[,.!?;]\\p{Han}")
        )
      )
    | "\($entry.key): \(.)"
  ' "$catalog")
  if [[ -n "$violations" ]]; then
    echo "Invalid $language spacing in $catalog:" >&2
    echo "$violations" >&2
    exit 1
  fi
done

echo "Chinese localization spacing checks passed."
