#!/bin/bash
# Manual GUI walkthrough of `set --from-clipboard` (#6, verify R8 finding 2).
# Run this in a NORMAL Terminal (not from an automation context): every step
# opens the confirmation dialog — click Store (or press ⌘S) unless told otherwise.
set -u
B="${1:-$(dirname "$0")/../release/CheKeychain}"
S="gui-walk-$$"
r() { echo; echo "▶ $*"; "$@"; echo "   rc=$?"; }
echo "binary: $B   service: $S"
echo
echo "=== 1/4 new item: copy → --from-clipboard → Store. Expect: ✓ stored … removed from this Mac's clipboard; clipboard empty afterwards."
printf 'walk-token-1' | pbcopy
r "$B" set --service "$S" --account a --from-clipboard
echo "   clipboard after: [$(pbpaste)] ($(pbpaste | wc -c | tr -d ' ') bytes — expect 0)"
echo
echo "=== 2/4 existing item: copy a new value → Store. Expect: dialog's FIRST line '⚠ replaces an existing secret'; ✓ stored."
printf 'walk-token-2' | pbcopy
r "$B" set --service "$S" --account a --from-clipboard
echo
echo "=== 3/4 existing item + --daemon → Store. Expect: FIRST line '⚠ replaces an existing secret AND makes it daemon-readable…'; ✓ stored … (daemon-readable…)."
printf 'walk-token-3' | pbcopy
r "$B" set --service "$S" --account a --from-clipboard --daemon
echo
echo "=== 4/4 clipboard changed while the dialog is open: when the dialog appears, copy something else (e.g. select text and ⌘C), THEN click Store. Expect: ✗ the clipboard changed while the dialog was open — nothing stored… exit 1; account b absent."
printf 'walk-token-4' | pbcopy
r "$B" set --service "$S" --account b --from-clipboard
r "$B" has --service "$S" --account b
echo
echo "=== cleanup"
r "$B" unset --service "$S"
echo "Done. Paste this whole output back to the session."
