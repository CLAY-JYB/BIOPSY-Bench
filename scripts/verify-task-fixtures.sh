#!/usr/bin/env bash
# Fixture integrity gate for BIOPSY-Bench tasks.
#
# Catches the "empty gitlink" failure class seen on
# patch-diffing/git-2.49.0-push-remoteref-leak: a fixture directory that was a
# live git repo at `git add` time commits as a submodule gitlink (mode 160000).
# A gitlink carries no content -- with no-network verification the files are
# unrecoverable, the verifier image's `dotgit -> .git` restore becomes a no-op,
# /app/repo/.git never exists, and the oracle scores 0 instead of 1.0. Nothing
# in `git status` flags this, because a gitlink's contents are ignored.
#
# The gate checks what actually ships (the committed tree, not the working
# tree), so run it after committing a task import:
#
#   scripts/verify-task-fixtures.sh              # check HEAD
#   scripts/verify-task-fixtures.sh --ref <rev>  # check any tree-ish
#
# Exit 0 = all fixtures intact; exit 1 = at least one failure (printed).

set -uo pipefail

REF=HEAD
if [ "${1:-}" = "--ref" ] && [ -n "${2:-}" ]; then
  REF=$2
else
  [ $# -eq 0 ] || { echo "usage: $0 [--ref <tree-ish>]" >&2; exit 2; }
fi

cd "$(git rev-parse --show-toplevel)" || exit 2
git cat-file -e "$REF^{tree}" 2>/dev/null || { echo "FAIL: not a tree-ish: $REF" >&2; exit 2; }

fail=0

# --- Gate 1: no submodule gitlinks anywhere in the bench --------------------
# A 160000 entry is never legitimate here: bench tasks must be self-contained
# (verification runs with no network), and a gitlink's objects live only in the
# nested repo that produced it.
while read -r mode _sha path; do
  [ "$mode" = "160000" ] || continue
  echo "FAIL: '$path' is committed as a submodule gitlink (mode 160000): its content is not in the repo and a fresh clone ships an empty directory. Re-add the directory contents as plain tracked files." >&2
  fail=1
done < <(git ls-tree -r --full-tree "$REF")

# --- Gate 2/3: dotgit fixtures survive the verifier image materialization ----
# Tasks that ship a git-dir fixture store it as plain files under
# tests/data-files/app/<name>/dotgit/ (a real .git/ directory cannot be
# committed -- it would become exactly the gitlink Gate 1 rejects). Their
# Dockerfile renames /app/<name>/dotgit -> /app/<name>/.git at build time.
# Replay that rename against ONLY the committed files (what COPY data-files/
# sees in the verifier) and require a functioning repository to come out.

for df in $(git ls-tree -r --full-tree --name-only "$REF" | grep '/tests/Dockerfile$'); do
  task=${df%/tests/Dockerfile}
  data=$task/tests/data-files
  dockerfile=$(git show "$REF:$df")

  if ! printf '%s' "$dockerfile" | grep -q dotgit; then
    # No restore expected -- but a tracked dotgit fixture without the restore
    # would ship as a literal /app/<name>/dotgit and break the trigger too.
    if git ls-tree -r --full-tree --name-only "$REF" -- "$data" | grep -q '/dotgit/'; then
      echo "FAIL: $task tracks a dotgit fixture but its Dockerfile has no dotgit->.git restore; the image would ship /app/<name>/dotgit and no .git." >&2
      fail=1
    fi
    continue
  fi

  tmp=$(mktemp -d)
  if ! git archive "$REF" -- "$data" 2>/dev/null | tar -x -C "$tmp"; then
    echo "FAIL: $task Dockerfile restores dotgit->.git but '$data' is missing from $REF." >&2
    rm -rf "$tmp"; fail=1; continue
  fi

  # Same loop as the Dockerfile, minus the leading / (archive root = data-files/).
  (cd "$tmp" && sh -c 'for d in app/*/dotgit; do if [ -d "$d" ]; then mv "$d" "${d%/dotgit}/.git"; fi; done')

  restored=0
  for g in "$tmp"/app/*/.git; do
    [ -d "$g" ] || continue
    restored=$((restored + 1))
    if ! refs=$(git --git-dir="$g" for-each-ref 2>/dev/null) || [ -z "$refs" ]; then
      echo "FAIL: $task: restored ${g#"$tmp"} is not a functioning git repository (for-each-ref failed or found no refs)." >&2
      fail=1
    fi
  done
  if [ "$restored" -eq 0 ]; then
    echo "FAIL: $task Dockerfile restores /app/*/dotgit -> .git but no dotgit files are committed under $data -- the restore is a no-op and /app/<name>/.git will not exist (fixture committed as a gitlink, or never added)." >&2
    fail=1
  fi
  rm -rf "$tmp"
done

if [ "$fail" -eq 0 ]; then
  echo "OK: no gitlinks; all dotgit fixtures tracked and restore to working .git dirs ($REF)"
fi
exit "$fail"
