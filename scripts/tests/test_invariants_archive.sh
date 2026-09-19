#!/usr/bin/env bash
# Exercise the real guard against complete source fixtures; no network.
# Git initialization is confined to default-mode fixtures. Archive lint never
# manufactures a Git repository or index.
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
REAL_PYTHON="$(command -v python3)"
REAL_GREP="$(command -v grep)"
fixture="$TMP/source"
ran=0 failed=0

make_fixture() {
  rm -rf "$fixture"
  mkdir -p "$fixture/docs/agent" "$fixture/docs/design" \
    "$fixture/scripts/lib" "$fixture/scripts/tests"
  cp "$ROOT/scripts/check-invariants.sh" "$fixture/scripts/check-invariants.sh"
  printf 'See docs/agent/architecture.md\n' > "$fixture/AGENTS.md"
  printf '# Architecture\n' > "$fixture/docs/agent/architecture.md"
  printf 'docs/\nscripts/\n' > "$fixture/docs/structure_zh.md"
  cp "$fixture/docs/structure_zh.md" "$fixture/docs/structure_en.md"
  local name
  for name in requirements architecture-overview agent-container multi-repo-isolation; do
    printf '# Design\n' > "$fixture/docs/design/${name}_zh.md"
  done
  printf '# put-role-policy fixture\n' > "$fixture/scripts/lib/roles.sh"
  printf '# checksum test fixture\n' > "$fixture/scripts/tests/test_codegraph_checksum.sh"
  cat > "$fixture/scripts/deploy-all.sh" <<'SH'
#!/usr/bin/env bash
# codegraph-acquire:begin
# codegraph-acquire:end
printf '%s\n' \
  'CODEGRAPH_SERVER_REPO=codegraph-ai/CodeGraph' \
  'CODEGRAPH_SERVER_EFFECTIVE_URL=https://github.com/codegraph-ai/CodeGraph/releases/test'
SH
}

run_lint() {  # run_lint default|archive [fault]
  local mode="$1" fault="${2:-}"
  # The native runner may pass archive mode to shell tests. Clear it explicitly
  # when exercising the default-mode contract.
  local -a command=(env -u SOURCE_TRUTH_SOURCE_ARCHIVE)
  if [[ "$mode" == archive ]]; then
    command+=(SOURCE_TRUTH_SOURCE_ARCHIVE=1)
  fi
  if [[ -n "$fault" ]]; then
    command+=("PATH=$TMP/bin:$PATH" "INVARIANTS_FAULT=$fault"
      "INVARIANTS_REAL_PYTHON=$REAL_PYTHON" "INVARIANTS_REAL_GREP=$REAL_GREP")
  fi
  rc=0
  out="$("${command[@]}" bash "$fixture/scripts/check-invariants.sh" 2>&1)" || rc=$?
}

expect_pass() {
  ran=$((ran + 1))
  if [[ "$rc" -eq 0 && "$out" == *"check-invariants: OK"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    failed=$((failed + 1))
    printf '  FAIL %s (rc=%s)\n%s\n' "$1" "$rc" "$out"
  fi
}

expect_fail() {
  ran=$((ran + 1))
  if [[ "$rc" -ne 0 && "$out" == *"$2"* && "$out" != *"check-invariants: OK"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    failed=$((failed + 1))
    printf '  FAIL %s (rc=%s)\n%s\n' "$1" "$rc" "$out"
  fi
}

printf 'test_invariants_archive:\n'
make_fixture
run_lint default
expect_fail "default mode rejects a source tree without Git" "no .git"

git init -q "$fixture"
run_lint default
expect_fail "default mode rejects an empty Git enumeration" "Git source inventory"
git -C "$fixture" add -A
run_lint default
expect_pass "default mode accepts a complete tracked fixture"

make_fixture
run_lint archive
expect_pass "explicit archive mode checks a complete source fixture"
[[ ! -e "$fixture/.git" ]]

mkdir -p "$fixture/docs/nested/deeper"
printf '# Pair\n' > "$fixture/docs/nested/deeper/guide_en.md"
run_lint archive
expect_fail "nested bilingual omissions are rejected" "双语缺配对"
cp "$fixture/docs/nested/deeper/guide_en.md" "$fixture/docs/nested/deeper/guide_zh.md"
run_lint archive
expect_pass "nested bilingual pairs remain valid"
printf '# Unpaired\n' > "$fixture/docs/nested/deeper/guide.md"
run_lint archive
expect_fail "docs wildcard includes deeper neutral Markdown" "DOC_CHINESE_ONLY"

make_fixture
printf 'fixture binary\n' > "$fixture/codegraph-server-fixture"
run_lint archive
expect_fail "forbidden engine binary remains rejected" "仓库里跟踪了引擎二进制"

make_fixture
printf '.hidden.txt\n' > "$fixture/.gitignore"
printf 'Work%s\n' 'Buddy' > "$fixture/.hidden.txt"
run_lint archive
expect_fail "hidden and ignored files still reach the keyword guard" "公开仓不可含"

make_fixture
# Split the offending URL across arguments so the test itself is safe to ship.
printf 'https://github.com/%s/%s\n' example-team source-truth > "$fixture/scripts/example.sh"
run_lint archive
expect_fail "archive source still enforces the public project slug" "项目安装入口未指向"

make_fixture
mkdir -p "$fixture/scripts/lib/nested"
{
  printf '# put-role-policy fixture\n'
  printf '%s:%s:*\n' arn:aws:logs '${REGION}'
} > "$fixture/scripts/lib/nested/role policy.sh"
run_lint archive
expect_fail "IAM wildcard spans subdirectories and preserves spaces" "全局共享角色策略 Resource 钉死"

make_fixture
printf 'plain text\n' > "$fixture/scripts/file with spaces.txt"
ln -s ../AGENTS.md "$fixture/scripts/agent-link"
run_lint archive
expect_pass "printable spaces and an internal file symlink are fully scanned"
ln -s AGENTS.md "$fixture/codegraph-server-link"
run_lint archive
expect_fail "symlink entries also reach the binary guard" "仓库里跟踪了引擎二进制"

make_fixture
printf 'outside fixture\n' > "$TMP/outside.txt"
ln -s "$TMP/outside.txt" "$fixture/scripts/external-link"
run_lint archive
expect_fail "links outside the delivered tree are rejected" "Source inventory failed"

make_fixture
ln -s missing-file "$fixture/scripts/broken-link"
run_lint archive
expect_fail "broken file symlinks cannot disappear from the inventory" "Source inventory failed"

make_fixture
ln -s ../docs "$fixture/scripts/directory-link"
run_lint archive
expect_fail "directory symlinks cannot be treated as readable files" "Source inventory failed"

make_fixture
printf 'fixture\n' > "$fixture/scripts/line"$'\n'"break.txt"
run_lint archive
expect_fail "newline paths cannot corrupt line-based check inputs" "unrepresentable source path"

make_fixture
mkfifo "$fixture/scripts/pipe"
run_lint archive
expect_fail "special files fail before any potentially blocking read" "regular file"

# Inject deterministic OS failures without production test hooks or chmod-based
# assertions that behave differently when validation runs as root.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/python3" <<'SH'
#!/usr/bin/env bash
exec "$INVARIANTS_REAL_PYTHON" -c '
import builtins
import os
from pathlib import Path
import sys

fault = os.environ["INVARIANTS_FAULT"]
real_scandir = os.scandir
real_open = builtins.open
if fault in ("enumeration", "empty"):
    class InterruptedEntries:
        def __init__(self, entries):
            self.entries = entries
            self.yielded = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.close()
        def __iter__(self):
            return self
        def __next__(self):
            if fault == "empty":
                raise StopIteration
            if self.yielded:
                raise PermissionError("forced enumeration error")
            self.yielded = True
            return next(self.entries)
        def close(self):
            self.entries.close()
    os.scandir = lambda path: InterruptedEntries(real_scandir(path))
elif fault == "read":
    def interrupted_open(file, *args, **kwargs):
        if Path(file).name == "read-error.txt":
            raise PermissionError("forced file read error")
        return real_open(file, *args, **kwargs)
    builtins.open = interrupted_open
sys.argv = sys.argv[1:]
exec(compile(sys.stdin.read(), "<source inventory fixture>", "exec"))
' "$@"
SH
cat > "$TMP/bin/grep" <<'SH'
#!/usr/bin/env bash
if [[ "$INVARIANTS_FAULT" == scan ]]; then
  for arg in "$@"; do
    if [[ "$arg" == scripts/read-error.txt ]]; then
      printf 'forced scan read error\n' >&2
      exit 2
    fi
  done
fi
exec "$INVARIANTS_REAL_GREP" "$@"
SH
chmod +x "$TMP/bin/python3" "$TMP/bin/grep"

make_fixture
printf 'fixture\n' > "$fixture/scripts/read-error.txt"
run_lint archive enumeration
expect_fail "partial enumeration followed by an error cannot pass" "forced enumeration error"
run_lint archive empty
expect_fail "empty enumeration fails even with complete files on disk" "Empty source inventory"
run_lint archive read
expect_fail "file read errors cannot be reported as a clean scan" "forced file read error"
run_lint archive scan
expect_fail "read errors after inventory validation also fail" "forced scan read error"

printf '  ran=%s failed=%s\n' "$ran" "$failed"
[[ "$failed" -eq 0 ]]
