#!/usr/bin/env bash
# check-versions.sh — 无网络版本钉死防漂移守卫（test.sh --lint / CI 调用）。
# 校验 AGENTS.md「基础镜像 + 依赖 EXACT-pin」硬约束中可机检的部分：
#   - agent-container 基础镜像必须按 sha256 digest 钉死（非浮动 tag）；
#   - requirements.txt 每个非注释依赖必须 ==<version> 精确钉死；
#   - agent-container requirements.lock 覆盖 direct pins；
#   - index-service requirements.lock 是完整、exact-pinned 的传递闭包，覆盖 direct pins，
#     且 bootstrap 必须从该 lock 安装；
#   - Node 主版本钉死（setup_<N>.x，不是浮动 setup_lts.x）；
#   - @anthropic-ai/claude-code npm 包 EXACT-pin（@<version>）。
# 失败即非零退出，逐条打印问题。纯文本检查，无 docker / 无网络。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DOCKERFILE="agent-container/Dockerfile"
REQ="agent-container/requirements.txt"
LOCK="agent-container/requirements.lock"

fail=0
err()  { printf '  ✗ %s\n' "$1" >&2; fail=1; }
ok()   { printf '  ✓ %s\n' "$1"; }
warn() { printf '  ! %s\n' "$1"; }  # advisory; does NOT set fail

echo "check-versions: $ROOT"

# 1. 基础镜像 digest 钉死
if [[ -f "$DOCKERFILE" ]]; then
  base="$(grep -E '^FROM ' "$DOCKERFILE" | head -1)"
  if [[ "$base" == *"@sha256:"* ]]; then ok "基础镜像按 sha256 digest 钉死"
  else err "基础镜像未按 digest 钉死（FROM 应含 @sha256:…）：$base"; fi
else err "缺少 $DOCKERFILE"; fi

# 2. requirements.txt 每个直接依赖 ==-钉死
# 先剥掉行内注释再判 ==，否则注释里出现的 == 会把未钉死依赖误判为已钉死
# （如 `requests  # see ==2.34.2` 或 `boto3>=1.43.31  # was ==…`）。与第 3 步
# lock 覆盖检查的归一化保持一致。
if [[ -f "$REQ" ]]; then
  unpinned="$(grep -vE '^\s*#' "$REQ" | sed -E 's/\s*#.*$//' | grep -vE '^\s*$' | grep -vE '==' || true)"
  if [[ -z "$unpinned" ]]; then ok "requirements.txt 全部 ==-钉死"
  else err "requirements.txt 有未钉死依赖：$(echo "$unpinned" | tr '\n' ' ')"; fi
else err "缺少 $REQ"; fi

# 3. requirements.lock 存在且覆盖 txt 的每个直接依赖（同名同版本）
if [[ -f "$LOCK" ]]; then
  ok "requirements.lock 存在"
  if [[ -f "$REQ" ]]; then
    while IFS= read -r dep; do
      [[ -z "$dep" ]] && continue
      # dep 形如 name==ver（去掉行尾注释/空白；并剥离 pip extras [x]，
      # 因为 lock 里的 pip freeze 不含 extras：requirements 写 httpx[http2]==X，
      # lock 是 httpx==X，需归一化后再比对，否则误报）。
      pin="$(echo "$dep" | sed -E 's/\s*#.*$//; s/\s//g; s/\[[^]]*\]//')"
      [[ -z "$pin" ]] && continue
      if grep -qixF "$pin" "$LOCK"; then :
      else err "requirements.txt 的 '$pin' 未在 requirements.lock 中同版本出现（改了 txt 忘了重生成 lock？）"; fi
    done < <(grep -vE '^\s*#' "$REQ" | grep -E '==')
    [[ "$fail" -eq 0 ]] && ok "requirements.txt 直接依赖均与 lock 一致"
  fi
else err "缺少 ${LOCK}（应由 docker build + pip freeze 生成的全传递依赖锁）"; fi

# 4. Node 主版本钉死（非浮动 lts）
if [[ -f "$DOCKERFILE" ]]; then
  # 只看真正的安装行、且先剥掉注释：这条守卫曾经 grep 'setup_<N>.x'，而 Dockerfile 里唯一
  # 匹配它的是一行**注释**（解释 `curl … setup_24.x | bash -` 这个管道已被移除）。真正的钉版本
  # 在 apt 源那行 `node_24.x`。于是把 node_24.x 改成 node_lts.x 守卫照样报绿 —— 只要注释还在。
  # 这与第 5 项 claude-code 的注释「只看 npm install 行，不看注释」是同一个坑，那里防住了，这里没有。
  node_line="$(sed -E 's/#.*$//' "$DOCKERFILE" | grep -E 'deb\.nodesource\.com/node_[0-9a-z]+\.x' || true)"
  if [[ -z "$node_line" ]]; then
    err "未找到 Node 的 apt 源安装行（deb.nodesource.com/node_<N>.x）"
  elif printf '%s' "$node_line" | grep -qE 'node_lts\.x'; then
    err "Node 用了浮动 node_lts.x（应钉主版本 node_<N>.x）"
  elif printf '%s' "$node_line" | grep -qE 'node_[0-9]+\.x'; then
    ok "Node 主版本钉死（$(printf '%s' "$node_line" | grep -oE 'node_[0-9]+\.x' | head -1)）"
  else
    err "Node 安装行未钉主版本：$node_line"
  fi

  # 5. claude-code npm: both installation paths must use the same exact semver.
  #    This proprietary package sits outside npm lock files, so @latest would make builds
  #    non-reproducible and leave THIRD-PARTY-LICENSES unable to state what shipped.
  cc_docker="$(grep -E 'npm install[^#]*@anthropic-ai/claude-code' "$DOCKERFILE" || true)"
  cc_host="$(grep -E 'npm install[^#]*@anthropic-ai/claude-code' index-service/bootstrap.sh || true)"
  cc_docker_ver="$(sed -nE 's/.*@anthropic-ai\/claude-code@([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<< "$cc_docker")"
  cc_host_ver="$(sed -nE 's/.*@anthropic-ai\/claude-code@([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<< "$cc_host")"
  if [[ -z "$cc_docker_ver" || -z "$cc_host_ver" ]]; then
    err "@anthropic-ai/claude-code 必须在 Dockerfile 与 bootstrap.sh 中使用 exact semver"
  elif [[ "$cc_docker_ver" != "$cc_host_ver" ]]; then
    err "@anthropic-ai/claude-code 版本不一致：Dockerfile=$cc_docker_ver bootstrap=$cc_host_ver"
  else
    ok "@anthropic-ai/claude-code exact-pin 一致（$cc_docker_ver）"
  fi
fi

# 6. index-service deps: requirements.txt records exact direct intent;
#    requirements.lock must contain the larger exact transitive closure, cover
#    every direct pin, and be the file bootstrap installs.
IDX_REQ="index-service/requirements.txt"
IDX_LOCK="index-service/requirements.lock"
IDX_BOOT="index-service/bootstrap.sh"
if [[ -f "$IDX_REQ" ]]; then
  idx_unpinned="$(grep -vE '^\s*#' "$IDX_REQ" | sed -E 's/\s*#.*$//' | grep -vE '^\s*$' | grep -vE '==' || true)"
  if [[ -z "$idx_unpinned" ]]; then ok "index-service/requirements.txt 全部 ==-钉死"
  else err "index-service/requirements.txt 有未钉死依赖：$(echo "$idx_unpinned" | tr '\n' ' ')"; fi
else err "缺少 $IDX_REQ"; fi

if [[ -f "$IDX_LOCK" ]]; then
  if grep -q 'INCOMPLETE' "$IDX_LOCK"; then
    err "$IDX_LOCK 仍标记为 INCOMPLETE"
  else
    ok "index-service/requirements.lock 是完整 lock（无 INCOMPLETE 标记）"
  fi
  idx_lock_unpinned="$(grep -vE '^\s*#' "$IDX_LOCK" | grep -vE '^\s*$' | grep -vE '^[A-Za-z0-9_.-]+==[^[:space:]]+$' || true)"
  if [[ -z "$idx_lock_unpinned" ]]; then ok "index-service lock 每项均为 exact pin"
  else err "index-service lock 含非 exact pin：$(echo "$idx_lock_unpinned" | tr '\n' ' ')"; fi
  if [[ -f "$IDX_REQ" ]]; then
    idx_direct_count=0
    while IFS= read -r dep; do
      [[ -z "$dep" ]] && continue
      pin="$(echo "$dep" | sed -E 's/\s*#.*$//; s/\s//g; s/\[[^]]*\]//')"
      [[ -z "$pin" ]] && continue
      idx_direct_count=$((idx_direct_count + 1))
      if grep -qixF "$pin" "$IDX_LOCK"; then :
      else err "index-service direct pin '$pin' 未在 lock 中同版本出现"; fi
    done < <(grep -vE '^\s*#' "$IDX_REQ" | grep -E '==')
    idx_lock_count="$(grep -vE '^\s*(#|$)' "$IDX_LOCK" | wc -l | tr -d ' ')"
    if [[ "$idx_lock_count" -gt "$idx_direct_count" ]]; then
      ok "index-service lock 含完整传递闭包（${idx_lock_count} 包 > ${idx_direct_count} direct pins）"
    else
      err "index-service lock 没有传递闭包（${idx_lock_count} 包 <= ${idx_direct_count} direct pins）"
    fi
  fi
else err "缺少 $IDX_LOCK（必须由真实 ARM64/Python 3.12 构建生成）"; fi

if [[ -f "$IDX_BOOT" ]]; then
  if grep -qE 'pip3? install[^|]*-r "?\$APP/requirements\.lock"?' "$IDX_BOOT"; then
    ok "bootstrap.sh 从 index-service/requirements.lock 安装"
  else
    err "bootstrap.sh 未从 requirements.lock 安装，传递依赖仍会漂移"
  fi
fi

# 7. The isolated glossary worker has its own lock. Guard both the intent pins and
#    their exact versions; validating only the agent lock misses a broken worker
#    install even when the agent's CI environment has all the missing dependencies.
if python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
def pins(path, *, extras=False):
    result = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern = r"([\w.-]+)(?:\[[\w,.-]+\])?==([A-Za-z0-9.!+_-]+)" if extras else r"([\w.-]+)==([A-Za-z0-9.!+_-]+)"
        match = re.fullmatch(pattern, line)
        if not match or "*" in line:
            raise ValueError(f"{path}:{number}: expected an exact name==version pin")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in result:
            raise ValueError(f"{path}:{number}: duplicate package {name}")
        result[name] = match[2]
    if not result:
        raise ValueError(f"{path}: empty dependency list")
    return result

try:
    direct = pins(root / "index-service/glossary-requirements.txt", extras=True)
    worker = pins(root / "index-service/glossary-requirements.lock")
    agent = pins(root / "agent-container/requirements.lock")
    for name, version in direct.items():
        if worker.get(name) != version:
            raise ValueError(f"glossary lock does not match direct pin {name}=={version}")
    for name, version in worker.items():
        if agent.get(name) != version:
            raise ValueError(f"glossary pin {name}=={version} is not in the agent lock / license inventory")
except (OSError, ValueError) as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
PY
then
  ok "glossary 直接依赖精确固定，独立 lock 与许可清单版本一致"
else
  err "glossary 依赖 / lock 不一致"
fi

echo ""
if [[ "$fail" -eq 0 ]]; then echo "check-versions: PASS"; else echo "check-versions: FAIL" >&2; fi
exit "$fail"
