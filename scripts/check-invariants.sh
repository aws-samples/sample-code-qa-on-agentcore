#!/usr/bin/env bash
# check-invariants.sh — 快速无网络结构 lint（pre-commit / test.sh --lint 调用）。
# 校验 AGENTS.md 约定中可机检的子集：唯一依据、双语配对、顶层目录
# 双向 diff（structure_zh.md 收录的顶层目录 ↔ 磁盘实际目录）。
# 失败即非零退出，逐条打印问题。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
err() { printf '  ✗ %s\n' "$1" >&2; fail=1; }
# 8b once called `warn` here when no such function existed: the branch died with
# "warn: command not found" and TRUNCATED the whole run — 8c and the PII scan never executed —
# while the script still exited 0, because this file deliberately does not use `set -e`. Advisory
# by design: it must NOT set `fail`, or a "please confirm this is deliberate" note becomes a
# build failure.
warn() { printf '  ! %s\n' "$1" >&2; }
ok()  { printf '  ✓ %s\n' "$1"; }

# All checks share one validated inventory. The default requires a real Git
# checkout. SOURCE_TRUTH_SOURCE_ARCHIVE=1 is only for a clean delivered source
# tree: enumerate everything, including hidden files and symlinks, without ignore
# rules. Never create Git metadata or fall back to an empty/partial inventory.
source_archive="${SOURCE_TRUTH_SOURCE_ARCHIVE:-0}"
if ! _inventory="$(python3 - "$ROOT" "$source_archive" <<'PY'
import os
from pathlib import Path
import stat
import subprocess
import sys


def safe_path(name):
    name.encode("utf-8", errors="strict")
    if (not name or name == "-" or not name.isprintable()
            or name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/"))):
        raise ValueError(f"Unsafe or unrepresentable source path: {name!r}")


def walk_error(error):
    raise error


try:
    root = Path(sys.argv[1]).resolve(strict=True)
    mode = sys.argv[2]
    if mode == "1":
        paths = []
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            for name in dirs + files:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                safe_path(relative)
                if name in files or path.is_symlink():
                    paths.append(relative)
    elif mode == "0":
        if not os.path.lexists(root / ".git"):
            raise ValueError("Cannot enumerate git-tracked files: source tree has no .git")
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root, check=True, stdout=subprocess.PIPE,
        )
        if not result.stdout or not result.stdout.endswith(b"\0"):
            raise ValueError("Empty or incomplete Git source inventory")
        paths = [os.fsdecode(name) for name in result.stdout[:-1].split(b"\0")]
    else:
        raise ValueError("SOURCE_TRUTH_SOURCE_ARCHIVE must be 0 or 1")

    inventory = []
    for name in sorted(set(paths)):
        safe_path(name)
        path = root / name
        try:
            path.lstat()
        except FileNotFoundError:
            if mode == "0":
                continue  # An unstaged deletion is not a file in the current tree.
            raise
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)  # Reject links outside the delivered tree.
        if not stat.S_ISREG(resolved.stat().st_mode):
            raise ValueError(f"Source path is not a regular file or file symlink: {name!r}")
        # Read every entry before publishing the inventory. This also rejects
        # unreadable/broken links and prevents non-text files from hiding I/O errors.
        with open(path, "rb") as stream:
            while stream.read(1024 * 1024):
                pass
        inventory.append(name)
    if not inventory:
        raise ValueError("Empty source inventory")
    print("\n".join(inventory))
except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
    print(f"Source inventory failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
)"; then
  err "无法取得完整源码清单 / Cannot obtain a complete source inventory"
  exit 1
fi
if [[ -z "$_inventory" ]]; then
  err "源码清单为空 / Empty source inventory"
  exit 1
fi
mapfile -t SOURCE_FILES <<< "$_inventory"
unset _inventory

tracked_files() {  # tracked_files [-z] [pathspec...]; * also matches directory separators.
  local format='%s\n' file pattern
  if [[ "${1:-}" == -z ]]; then format='%s\0'; shift; fi
  for file in "${SOURCE_FILES[@]}"; do
    if [[ "$#" -eq 0 ]]; then
      printf "$format" "$file" || return "$?"
    else
      for pattern in "$@"; do
        if [[ "$file" == $pattern || "$file" == "${pattern%/}/"* ]]; then
          printf "$format" "$file" || return "$?"
          break
        fi
      done
    fi
  done
  return 0
}

# grep's "no match" is normal; command/read errors must remain nonzero, including
# inside command substitutions and pipelines where errexit alone is insufficient.
grep_matches() {
  local rc=0
  grep "$@" || rc=$?
  [[ "$rc" -le 1 ]] || return "$rc"
  return 0
}
scan_files() {  # NUL-delimited inventory on stdin, grep options/pattern in argv.
  local file
  while IFS= read -r -d '' file; do
    [[ -n "$file" ]] || continue
    grep_matches "$@" -- "$file" || return "$?"
  done
  return 0
}
grep_presence() {
  local rc=0
  grep "$@" >/dev/null || rc=$?
  if [[ "$rc" -eq 0 ]]; then printf 'match'
  elif [[ "$rc" -ne 1 ]]; then return "$rc"; fi
  return 0
}

echo "check-invariants: $ROOT"

# 1. AGENTS.md 存在
if [[ -f AGENTS.md ]]; then ok "AGENTS.md 存在"; else err "缺少 AGENTS.md（AI 约定的唯一依据）"; fi

# 2. docs/agent/architecture.md 存在且被 AGENTS.md 引用
if [[ -f docs/agent/architecture.md ]]; then ok "docs/agent/architecture.md 存在"
else err "缺少 docs/agent/architecture.md"; fi
grep -q 'docs/agent/architecture.md' AGENTS.md || err "AGENTS.md 未引用 docs/agent/architecture.md"

# 中文独有文档白名单：第 3 项（配对）与第 3b 项（枚举）共用，所以在两者之前声明。
DOC_CHINESE_ONLY=(
  # 设计依据文档，已在 docs/design/README.md 自我声明为中文
  "docs/design/README.md"
  "docs/design/requirements_zh.md"
  "docs/design/architecture-overview_zh.md"
  "docs/design/agent-container_zh.md"
  "docs/design/multi-repo-isolation_zh.md"
  # 研究性笔记（spike），结论已被 architecture / README 吸收
  "docs/agent/cardkit-streaming-spike.md"
  "docs/agent/indexing-performance-spike.md"
  "docs/agent/perf-comparison.md"
  # 面向贡献者与 AI 协作者的约定，主语言中文（AGENTS.md 自身已声明）
  "docs/README.md"
  "docs/agent/architecture.md"
  "docs/agent/invariants.md"
  "docs/glossary.md"
  "docs/agent/glossary.md"
  "docs/agent/playbooks.md"
  "docs/agent/TEMPLATE-spike.md"
  # AWS Samples security-review evidence is maintained in English.
  "docs/security-threat-model.md"
)

# 3. 双语 _en/_zh 配对：docs/ 下每个 *_en.md 必须有 *_zh.md，反之亦然
#    必须递归。原先用的是 shell glob `docs/*_en.md`，**不跨目录**；而第 3b 项对任何以
#    `_en.md`/`_zh.md` 结尾的文件直接 continue，理由写的是"成对文件由第 3 项检查过"——这个信任
#    对子目录并不成立。于是 docs/agent/deploy_en.md 没有中文版可以完全通过，而
#    docs/agent/runbook_zh.md 没有英文版正是最初那次事故本身。
#    又一次"文件名属性即豁免"：这次豁免的是"带双语后缀且位于子目录"。
#    用 git pathspec 递归（git 的 `*` 跨 `/`），失败即硬失败（见上面的可枚举性断言）。
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  # 已显式豁免为中文独有的文档不要求配对（名单在第 3b 项，声明在此之前使用）。
  _ex=0; for e in "${DOC_CHINESE_ONLY[@]}"; do [[ "$f" == "$e" ]] && { _ex=1; break; }; done
  [[ $_ex -eq 1 ]] && continue
  case "$f" in
    *_en.md) [[ -f "${f%_en.md}_zh.md" ]] || err "双语缺配对：$f 缺少对应的 _zh.md" ;;
    *_zh.md) [[ -f "${f%_zh.md}_en.md" ]] || err "双语缺配对：$f 缺少对应的 _en.md" ;;
  esac
done <<< "$(tracked_files 'docs/**_en.md' 'docs/**_zh.md')"
[[ $fail -eq 0 ]] && ok "docs/ 双语 _en/_zh 配对完整（含子目录）"

# 3b. 每个 docs/ 下的 md 必须"要么成对，要么被显式豁免"。
#     旧写法只 glob docs/*_en.md ↔ docs/*_zh.md，于是**中性文件名等于自动豁免**：runbook.md
#     （整个部署 / 接入飞书 / 验证 / 运维 / 排障流程都在里面）就这样绕过了检查，structure_en.md
#     里甚至把这个豁免写成了"设计如此"。结果是：唯一能发现"英文读者无法部署"的机械检查，恰好
#     把最大的那份文档排除在外。
#     改成白名单模型：新增一份中文独有文档，必须显式写进 DOC_CHINESE_ONLY —— 那是一个在 review
#     里看得见的决定，而不是一次悄悄的默认。
# 故意不在名单里：runbook —— 它是英文 README 六次指向的唯一部署/接入/验证/排障流程，中文独有
# 等于英文读者无法部署。所以它必须是 runbook_en.md / runbook_zh.md 一对（现已成对）。
doc_pair_ok=1
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  base="${f##*/}"
  # 成对文件由 3 已经检查过
  [[ "$base" == *_en.md || "$base" == *_zh.md ]] && continue
  exempt=0
  for e in "${DOC_CHINESE_ONLY[@]}"; do [[ "$f" == "$e" ]] && { exempt=1; break; }; done
  [[ $exempt -eq 1 ]] && continue
  err "docs/ 下的 $f 既不是 _en/_zh 配对，也未列入 DOC_CHINESE_ONLY 豁免名单（新增中文独有文档须显式声明）"
  doc_pair_ok=0
done <<< "$(tracked_files 'docs/*.md')"
[[ "$doc_pair_ok" -eq 1 ]] && ok "docs/ 下每份文档要么成对、要么已显式豁免"

# 4. 结构文档存在
[[ -f docs/structure_zh.md && -f docs/structure_en.md ]] \
  && ok "结构文档双语齐全" || err "缺少 docs/structure_{zh,en}.md"

# 5. 顶层目录 ↔ structure_zh.md 双向对齐（AGENTS.md：改顶层目录必须同步结构文档）
#    文档侧：代码块里顶格的 `xxx/` 行；磁盘侧：仓库根的实际目录（.git 与 gitignore 的
#    .local 除外——.local 在文档中有收录但不要求磁盘存在）。
if [[ -f docs/structure_zh.md ]]; then
  doc_dirs="$(grep -oE '^[A-Za-z0-9_.-]+/' docs/structure_zh.md | tr -d '/' | sort -u)"
  disk_dirs="$(find . -maxdepth 1 -mindepth 1 -type d ! -name '.git' ! -name '.local' \
    -print | sed 's|^\./||' | sort -u)"
  struct_ok=1
  while IFS= read -r d; do
    [[ -z "$d" || "$d" == ".local" ]] && continue
    [[ -d "$d" ]] || { err "structure_zh.md 收录的顶层目录磁盘上缺失: $d"; struct_ok=0; }
  done <<< "$doc_dirs"
  while IFS= read -r d; do
    [[ -z "$d" || "$d" == .* ]] && continue
    # Skip anything git already ignores. The dot-prefix skip above covers .local/ and friends, but
    # NOT non-dotted generated dirs — venv/, coverage/, dist/, reports/, cdk.out/. A developer who
    # follows the README and creates a virtualenv in the repo root would fail this lint, and an
    # unexplained red in the lint layer is how people learn to stop running the suite.
    if [[ "$source_archive" == "0" ]]; then
      git check-ignore -q -- "$d" 2>/dev/null && continue
    fi
    [[ $'\n'"$doc_dirs"$'\n' == *$'\n'"$d"$'\n'* ]] \
      || { err "顶层目录未收录进 structure_zh.md: $d（改顶层目录须同步结构文档）"; struct_ok=0; }
  done <<< "$disk_dirs"
  [[ "$struct_ok" -eq 1 ]] && ok "顶层目录与 structure_zh.md 双向一致"
fi

# 6. 设计权威依据已导入（structure_*.md 收录的 design/ 权威依据；改名/删除须同步两处）
for f in docs/design/requirements_zh.md docs/design/architecture-overview_zh.md \
         docs/design/agent-container_zh.md docs/design/multi-repo-isolation_zh.md; do
  [[ -f "$f" ]] && ok "设计权威依据: $f" || err "缺少设计权威依据: $f"
done

# 7. 全局共享 IAM 角色的策略 Resource 不得钉死 ${REGION}
#    source-truth-index-role / source-truth-dau-lambda-role 是账号级全局角色，被多区域共用，
#    而 put-role-policy 是覆盖写：策略 Resource ARN 若钉单区 ${REGION}，第二区域部署会改写它、
#    静默撤销第一区域的权限（2026-06-29 新加坡部署据此打挂东京）。这些资源型 ARN 的 region 段
#    必须用 '*'，靠 account + 资源名前缀兜底。只查易越权的服务面（lambda/events 的 ARN 是按区
#    构造的合法用法，不在此列）。
# 改名/删除任一文件都曾让这条守卫静默通过（硬编码路径 + 2>/dev/null || true —— 正是紧邻的
# 第 8 项注释里写着"被烧过"的那个构造）。改成枚举所有写 IAM 内联策略的脚本，并断言这些文件
# 确实存在：文件不见了要报错，而不是当作没有违规。
iam_policy_files="$(tracked_files -z 'scripts/lib/*.sh' 'scripts/*.sh' \
  | scan_files -lE 'put-role-policy|iam:PutRolePolicy')"
if [[ -z "$iam_policy_files" ]]; then
  err "找不到任何写 IAM 内联策略的脚本——第 7 项（多区域 Resource 守卫）无从检查，视为失败"
fi
guard_hits="$(printf '%s\n' "$iam_policy_files" | tr '\n' '\0' \
  | scan_files -HnE 'arn:aws:(logs|bedrock|bedrock-agentcore|secretsmanager|s3[a-z-]*):[a-z0-9-]*\$\{REGION\}:')"
if [[ -n "$guard_hits" ]]; then
  err "全局共享角色策略 Resource 钉死了 \${REGION}（多区部署会互相覆盖，改用 '*'）："
  printf '      %s\n' "$guard_hits" >&2
else
  ok "全局共享角色策略 Resource 未钉死 \${REGION}（多区域安全）"
fi

# 8. 项目安装入口须指向正式公开仓 aws-samples/sample-code-qa-on-agentcore。
#    同时匹配旧项目名，以拦住历史 sample 地址回流；引擎上游另由 8b 检查。
#    枚举所有已跟踪的 shell/Markdown 文件，避免文档更名后漏检。
slug_files="$(tracked_files '*.sh' '*.md' | grep_matches -vFx 'scripts/check-invariants.sh')"
slug_hits="$(printf '%s\n' "$slug_files" | tr '\n' '\0' \
  | scan_files -HIoE '(github\.com/|githubusercontent\.com/|:-)[A-Za-z0-9_.-]+/(source-truth|sample-code-qa-on-agentcore|sample-code-qa-on-agentcore)' \
  | grep_matches -vE 'aws-samples/sample-code-qa-on-agentcore$')"
if [[ -n "$slug_hits" ]]; then
  err "项目安装入口未指向公开仓 aws-samples/sample-code-qa-on-agentcore："
  printf '      %s\n' "$slug_hits" >&2
else
  ok "项目 GitHub 入口均为 aws-samples/sample-code-qa-on-agentcore"
fi

# 8b. 引擎二进制不得由本仓分发
#     codegraph-server 是上游 Apache-2.0 项目的产物（github.com/codegraph-ai/CodeGraph）。把默认
#     下载源指回本仓意味着两件坏事：本仓成了 Apache-2.0 二进制的再分发方（连带 NOTICE 义务），
#     且每个外部用户的部署都依赖我们给自己的 release 挂资产——那正是此前"外部用户根本装不上"的
#     成因。项目入口合法不代表能把本项目当作引擎上游，所以单列一条。
#     判定依据是 deploy-all.sh --print-engine-source 的输出，即 bash 在所有赋值执行完之后
#     真正解析到的值——而不是某一行源码。前一版按 `^CODEGRAPH_SERVER_REPO=` grep，有三条真实的
#     回退路径能大摇大摆走过去：只改 CODEGRAPH_SERVER_URL_DEFAULT 而不动 _REPO（curl 层读的是
#     ${CODEGRAPH_SERVER_URL:-$CODEGRAPH_SERVER_URL_DEFAULT}，改它一处就把整条路重定向了）；
#     在文件后面加一条**带缩进**的重新赋值（bash 取最后一次，`^` 锚点只看到第一次）；以及
#     把项目仓本身当作引擎源。让守卫读 bash 读到的东西，覆盖改名、缩进、续行、二次赋值和变量拼接。
if ! cg_src="$(bash scripts/deploy-all.sh --print-engine-source)"; then
  err "无法解析引擎来源 / Engine source command failed"
  cg_src=""
fi
cg_repo="$(printf '%s\n' "$cg_src" | sed -n 's/^CODEGRAPH_SERVER_REPO=//p')"
cg_url="$(printf '%s\n' "$cg_src" | sed -n 's/^CODEGRAPH_SERVER_EFFECTIVE_URL=//p')"
if [[ -z "$cg_repo" || -z "$cg_url" ]]; then
  err "deploy-all.sh --print-engine-source 无输出（该模式被删或提前退出了，本条守卫已失效）"
elif printf '%s %s' "$cg_repo" "$cg_url" | grep -qE 'source-truth|sample-code-qa-on-agentcore'; then
  err "引擎下载源指回了本仓——本仓不分发 codegraph-server（Apache-2.0，含 NOTICE 义务）："
  printf '      repo=%s\n      url=%s\n' "$cg_repo" "$cg_url" >&2
elif ! printf '%s' "$cg_repo" | grep -q 'codegraph-ai/CodeGraph'; then
  warn "引擎来源不是已知上游，请确认是有意的：repo=$cg_repo"
elif ! printf '%s' "$cg_url" | grep -q 'codegraph-ai/CodeGraph'; then
  err "引擎 repo 指向上游，但实际下载 URL 不是——两者必须一致："
  printf '      repo=%s\n      url=%s\n' "$cg_repo" "$cg_url" >&2
else
  ok "引擎二进制来自上游，本仓不再分发（按运行时解析值判定）"
fi

#     ……以及它绝不能作为文件进到仓库里。上面那条只看下载源的配置值，看不出树里是不是躺着一个
#     二进制。而 deploy-all.sh 的失败提示恰好教操作员把它放在仓库根目录并让 CODEGRAPH_SERVER_BIN
#     指向 $PWD，所以"照我们自己的指示做"就是它被提交的最可能路径。实测过：根目录放一个假二进制，
#     git add -A 会收，而当时两个守卫都报绿。
cg_tracked="$(tracked_files 'codegraph-server*' | grep_matches -vE '\.md$')"
if [[ -n "$cg_tracked" ]]; then
  err "仓库里跟踪了引擎二进制——本仓不分发它（Apache-2.0，含 NOTICE 义务）："
  printf '      %s\n' "$cg_tracked" >&2
else
  ok "仓库未跟踪引擎二进制"
fi

# 8c. 引擎二进制的校验行为必须由可执行测试守着，而不是由本文件断言
#     这条原来是 `grep -q 'sha256sum "$CG_TMP"'`。它对真正发生过的缺陷完全无效：那段校验调用了
#     只定义在 teardown.sh 里的 is_set，`if <不存在的命令>` 返回 127、在 if 条件位置不触发
#     set -e，于是恒走 else 分支把未校验字节暂存进 S3——而 grep 看到那一行"存在"，报绿。
#     实测对比：把该缺陷注入回去，scripts/tests/test_codegraph_checksum.sh 挂 7 条断言，
#     而原来的 8c 依旧打印"✓ 校验 sha256"。所以这里只断言**行为测试接上了**，行为本身交给它。
if [[ ! -f scripts/tests/test_codegraph_checksum.sh ]]; then
  err "缺少 scripts/tests/test_codegraph_checksum.sh（引擎二进制校验的行为测试）"
elif ! grep -q 'codegraph-acquire:begin' scripts/deploy-all.sh 2>/dev/null \
     || ! grep -q 'codegraph-acquire:end' scripts/deploy-all.sh 2>/dev/null; then
  err "deploy-all.sh 缺少 codegraph-acquire 哨兵注释——行为测试将抽不到被测块（会静默空转）"
else
  ok "引擎二进制校验由可执行测试覆盖（哨兵与测试文件均在）"
fi

# 9. 公开仓不得包含可识别到具体组织的内容
#    规则：不得含具体部署环境的描述、交付责任人/交付物表、真实人名或竞品对标。
#
#    历史教训（刻意不复述被清理的内容本身 —— 这个文件曾经就是唯一复述它的地方，而它按设计不扫
#    自己，于是成了唯一的盲区）：早期版本只 grep 少量写死的人名、且只扫 docs/，因此在一棵仍有
#    违规内容的树上报告全绿。写死名字只拦得住已经知道的词，拦不住下一份内部文档，所以现在扫全部
#    被 git 跟踪的文件、并按**结构性信号**判断。
#    它仍然拦不住纯叙述性的段落 —— 那需要人工过一遍 docs/design/ 与 docs/agent/*spike*，
#    这一点写在发布检查清单里，也写在下面的成功提示里。
PII_PATTERNS=(
  '客户环境' '客户侧' '客户内网' '贵司' '会上已' '会上澄清' '责任人' '交付物'
  'PoC 客户' '试点客户'   # 注：'内网地址' 曾在此，但它是通用安全术语（system.md 用它写
                        # 「绝不输出内网地址」这条规则），属于低信号高误报，已移除。
  '需求评审' '需客户'
  # 竞品对标的**类别**信号，而不是产品名：类别信号能拦住换个产品名重写的同类内容，
  # 而写死产品名只能拦住那两个。
  '对标' '竞品对比'
  # 那两个具体产品名仍然要拦，但按片段拼出来，避免这个文件本身携带字面量 ——
  # 它是唯一不被扫描的文件，不应该成为唯一复述这些名字的地方。请勿"顺手清理"成字面量。
  "$(printf 'Work%s' 'Buddy')" "$(printf 'Gen%s' 'Spark')"
)
# 逃生口。第 3b 项有 DOC_CHINESE_ONLY —— 一个在 review 里看得见、必须写理由的豁免机制；而第 9 项
# 此前**只有"改写措辞"一条路**。问题在于：'责任人' / '交付物' 是中文技术文档里的普通词（升级路径
# 表天然想要一列叫"责任人"，里程碑说明天然会写"交付物"），而裸「客户」在树里已出现于 17 个文件。
# 一旦出现第一个无法改写的合法命中（比如一个表格列头），唯一剩下的动作就是去动 PII_PATTERNS ——
# 也就是注释明令禁止的那件事。当年那个"只 grep 五个人名"的版本，很可能就是这么长出来的。
#
# 所以逃生口不是模式集的对立面，而正是**防止模式集被削弱**的东西：要豁免就写在这里，带路径、
# 带模式、带理由，让它在 review 里可见。散文能改措辞就改措辞；结构化内容改不动时走这里。
PII_EXEMPT=(
  # "路径|模式|理由" —— 三段都必填
)
_pii_exempt() {  # _pii_exempt <file> ; 0 = 已豁免
  local f="$1" e
  # 空豁免表是常态（当前就是空的），所以这里必须用安全形式：bash 4.2 会把空数组的裸展开当作
  # unbound variable 并 abort，而这个函数只在第 9 项真的命中时才被调用 —— 于是缺陷藏在一条
  # 平时不走的路径上，只在 test_invariants_archive 构造命中场景时暴露，且只在 AL2 上。
  for e in ${PII_EXEMPT[@]+"${PII_EXEMPT[@]}"}; do
    [[ "$f" == "${e%%|*}" ]] && return 0
  done
  return 1
}
# 裸「客户」单独处理：它是最强的信号，但 '客户端'（client-side）是完全合法的技术词，
# 全仓都在用。所以先删掉 '客户端' 再匹配剩下的「客户」—— 这样 '客户调研' / '贴近客户特征'
# / '客户的' / '客户商业美术资源' / '客户接入时' 都会命中，而 '客户端引擎' 不会。
# 为什么加这条：前两版守卫都是固定词表，而真正漏掉的内容（一整节客户确认问卷、五处
# 「客户」归因、客户技术栈）没有一处用到词表里的词。词表拦得住已经知道的，拦不住下一份。
# 这个守卫本身必须排除在主扫描之外（它必然含有整套模式），但那意味着它是唯一不被检查的文件 ——
# 而它恰好曾经是唯一复述机密结构的文件。所以单独用一组**叙述性**标记检查它自己：这些词不在
# PII_PATTERNS 里，所以不会自匹配，但正是上一次真正泄漏出去的那几个词。
GUARD_NARRATIVE_MARKERS='仓库拓扑|团队规模|交付行动表|自建 Git|分支策略|会上已澄清'
# 排除这条检查自己的那几行：标记列表本身就含有这些词，不排除的话它永远自己命中
# （第一版就是这样 —— 又一次自指失效，和这个会话里反复出现的那一类完全同形）。
narrative_hits="$(grep_matches -v 'GUARD_NARRATIVE_MARKERS' "$0" \
  | grep_matches -E "$GUARD_NARRATIVE_MARKERS")"
if [[ -n "$narrative_hits" ]]; then
  err "check-invariants.sh 自身复述了机密内容的结构（命中：$GUARD_NARRATIVE_MARKERS）。"
  printf '      这个文件按设计不被第 9 项扫描，所以它是唯一的盲区 —— 只写规则与教训，不要复述被清理的内容。\n' >&2
fi

PII_BARE_CUSTOMER='客户'
pii_re="$(IFS='|'; printf '%s' "${PII_PATTERNS[*]}")"
# 这个守卫本身必然包含上面的字面量，扫自己等于永远失败，所以排除它。
# The validated inventory includes every delivered file in archive mode.
# Do not filter it again by existence, ignore rules, or directory names.
pii_scan_list="$(tracked_files | grep_matches -vFx 'scripts/check-invariants.sh')"
pii_hits="$(printf '%s\n' "$pii_scan_list" | tr '\n' '\0' \
  | scan_files -IlE "$pii_re")"
# 裸「客户」：逐文件把 '客户端' 抹掉后再找「客户」，避免 client-side 的误报。
pii_bare=""
while IFS= read -r _f; do
  [[ -z "$_f" ]] && continue
  bare_hit="$(sed 's/客户端//g' -- "$_f" | grep_presence -F "$PII_BARE_CUSTOMER")"
  if [[ -n "$bare_hit" ]]; then
    pii_bare="${pii_bare}${_f}"$'\n'
  fi
done <<< "$pii_scan_list"
# 应用豁免表（带理由的显式决定；见 PII_EXEMPT 上方的说明）。
_filter_exempt() { while IFS= read -r _f; do [[ -z "$_f" ]] && continue; _pii_exempt "$_f" || printf '%s\n' "$_f"; done; }
pii_hits="$(printf '%s\n' "$pii_hits" | _filter_exempt)"
pii_bare="$(printf '%s\n' "$pii_bare" | _filter_exempt)"
if [[ -n "$pii_hits" || -n "$pii_bare" ]]; then
  err "文件中出现客户 / 交付责任人 / 真实人名 / 竞品名信号（公开仓不可含）："
  [[ -n "$pii_hits" ]] && printf '      %s\n' "$pii_hits" >&2
  [[ -n "$pii_bare" ]] && printf '      [裸「客户」，已排除「客户端」] %s\n' "$(printf '%s' "$pii_bare" | tr '\n' ' ')" >&2
  printf '      命中的模式集见 check-invariants.sh 第 9 项；若为误报请改写措辞，不要放宽模式。\n' >&2
else
  # 措辞刻意保守：这是一个词表 + 一个裸词，拦不住纯叙述性的段落。前三轮每一次漏掉的都是
  # 叙述而不是关键词，所以这里只能声称"未命中已知信号"，不能声称"干净"。
  ok "未命中已知客户 / 交付 / 人名 / 竞品信号（词表检查，不替代人工审阅 docs/design 与 docs/agent/*spike*）"
fi

# 10. bash<4.4 下 `set -u` + 空数组裸展开 = unbound variable，脚本直接 abort
#
# 这一条是被一个花了十五个 CR revision 才定位的失败逼出来的。`"${arr[@]}"` 在 bash 5.2
# （AL2023，本仓所有开发机）下把空数组展开为空，在 bash 4.2（AL2）下报 unbound variable
# 并 abort。所以这类缺陷在本地 100% 报绿，只在 build 镜像上炸 —— 而 install.sh /
# deploy-all.sh / launch-host.sh 是在**目标主机**上跑的，这个仓库要发到 aws-samples，
# 目标 OS 不由我们决定。
#
# 无法用行为测试守：本地任何 bash 都不复现。所以只能静态查，而静态查必须处理一个陷阱 ——
# 修好的形式 `${arr[@]+"${arr[@]}"}` 内部**包含**裸形式的字符串，第一版扫描器因此把已修的
# 代码也报成缺陷。故先删掉受保护的形式再找残留。
#
# 只对声明为 `name=()` 的变量报：确定非空的数组用裸展开是安全的，也更好读。
#
# 覆盖面是这一项自己的教训。第一版只查带引号的 [@] 形式，于是 revision 18 的 dry run 死在
# install.sh 第 519 行的一个 [*] 形式裸展开上 —— 同一个缺陷，换了下标，而这一项照样报 OK。
# 所以四种危险形态在这里一次枚举完：[@] 与 [*]，各自带引号与不带引号。
# 取长度的形式（`#` 前缀）不在其中：对空数组返回 0，不触发 unbound。
#
# 这段注释刻意不写出裸展开的字面形式。写出来它就会被本项自己的模式命中 —— 第一版这样做，于是
# 这个文件被自己报成缺陷。同一个自指陷阱第 9 项也有，那里的结论是：守卫不要复述它所守卫的东西。
#
# 修复形式取决于展开出现在哪里，三种，混用会引入新缺陷：
#   1. 独立参数位、[@]  → ${arr[@]+"${arr[@]}"}   语义是「零个或多个参数」，**不能**加外层引号
#                                                  （加了会在空时传一个空参数，改变 argc）
#   2. 独立参数位、[*]  → "${arr[*]-}"            语义是「一个字符串」，**必须**加外层引号
#                                                  （不加会在空时整个词消失，改变 argc）
#   3. 嵌在更长的字符串里（两种下标皆然）→ 只加 -，引号已由外层字符串提供
# 第 3 种是修 revision 19 时才补上的：前两种的 sed 要求引号紧贴展开，于是
# `say err "…: ${arr[*]}"` 这类一个都没匹配上，而它们恰好是多数。
unsafe_expand=""
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  grep -qE '^[[:space:]]*set -[a-z]*u' "$f" 2>/dev/null || continue
  # 该文件里声明为空数组的变量名。
  # `|| true` 不是装饰：本文件跑在 set -e 下，grep 无匹配返回 1，命令替换里的非零会直接
  # 终止整个脚本——第一版就是这样让 check-invariants 在这一项之前静默中止的。
  vars="$(grep -oE '^[[:space:]]*(local([[:space:]]+-[a-zA-Z]+)*[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=\(\)' "$f" 2>/dev/null \
          | sed -E 's/.*[[:space:]]//; s/=\(\)//' | sort -u || true)"
  # 一行可以声明多个：`local -a others=() failed=()` —— 只取行首那个会漏掉 failed，
  # 而 failed 正是 revision 18 炸掉的那一个。所以再扫一遍行内的其余声明。
  vars_inline="$(grep -oE '[A-Za-z_][A-Za-z0-9_]*=\(\)' "$f" 2>/dev/null \
          | sed -E 's/=\(\)//' | sort -u || true)"
  # 声明还可以跨行：
  #     PII_EXEMPT=(
  #       # 说明
  #     )
  # 这样的数组同样是空的，同样会在 bash 4.2 上 abort，但上面两个扫描都要求 `=()` 挨在一起，
  # 所以两个都看不见它。revision 19 就是这样漏掉 check-invariants.sh 自己第 391 行的裸展开：
  # 这一项报 OK，而 test_invariants_archive 在 AL2 上死于 PII_EXEMPT[@] unbound。
  # 「空」的判据是声明与收尾的 `)` 之间只有空白和注释 —— 有任何元素就不是空数组，裸展开安全。
  vars_multiline="$(awk '
    /^[[:space:]]*(local([[:space:]]+-[a-zA-Z]+)*[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=\([[:space:]]*$/ {
      n = $0
      sub(/^[[:space:]]*/, "", n)
      sub(/^local([[:space:]]+-[a-zA-Z]+)*[[:space:]]+/, "", n)
      sub(/=\(.*$/, "", n)
      empty = 1
      while ((getline line) > 0) {
        if (line ~ /^[[:space:]]*\)/) break
        if (line ~ /^[[:space:]]*$/) continue
        if (line ~ /^[[:space:]]*#/) continue
        empty = 0
      }
      if (empty) print n
    }
  ' "$f" 2>/dev/null | sort -u || true)"
  vars="$(printf '%s\n%s\n%s\n' "$vars" "$vars_inline" "$vars_multiline" | grep -v '^$' | sort -u || true)"
  [[ -n "$vars" ]] || continue
  # 先抹掉**受保护**的形式，否则修复本身含有裸形式的字符串，扫描器会把已修的代码报成缺陷
  # （第一版就是这样）。两种下标的保护形式都要抹。
  stripped="$(sed -E \
      -e 's/[$][{][A-Za-z_][A-Za-z0-9_]*\[@\]\+"[$][{][A-Za-z_][A-Za-z0-9_]*\[@\]\}"\}//g' \
      -e 's/[$][{][A-Za-z_][A-Za-z0-9_]*\[\*\]\+"[$][{][A-Za-z_][A-Za-z0-9_]*\[\*\]\}"\}//g' \
      -e 's/"[$][{][A-Za-z_][A-Za-z0-9_]*\[[@*]\](:?-)[^}]*\}"//g' \
      -e 's/[$][{][A-Za-z_][A-Za-z0-9_]*\[[@*]\](:?-)[^}]*\}//g' \
      "$f" || true)"
  for v in $vars; do
    # `${v[@]}` / `${v[*]}` with the closing brace RIGHT AFTER `]` — i.e. no `+`, `-`, `:-`
    # operator, which is exactly what makes an expansion safe. Quoting is not part of the
    # pattern: an unquoted bare expansion aborts on bash 4.2 just the same.
    hits="$(printf '%s\n' "$stripped" | grep -nE "[\$][{]$v\[[@*]\][}]" | cut -d: -f1 | tr '\n' ',' || true)"
    if [[ -n "$hits" ]]; then
      unsafe_expand="${unsafe_expand}${f}:${v}(行 ${hits%,}) "
    fi
  done
# tracked_files，不是 git ls-files。第一版用了后者，而 build 跑在 review-source 树上——那不是
# 一个 git 仓库，git ls-files 静默返回零个文件，于是这一项在 build 里报绿而什么都没扫。这个
# 文件顶部的注释早就写明了这一点（"Never create Git metadata or fall back to an empty/partial
# inventory"），SOURCE_FILES 就是为此存在的：清单取不到时脚本在第 98 行就退出，空转不可能发生。
done < <(tracked_files '*.sh')

if [[ -n "$unsafe_expand" ]]; then
  err "set -u 下存在空数组裸展开（bash<4.4 会 abort，AL2 上必炸；[@] 用 \${arr[@]+\"\${arr[@]}\"}，[*] 用 \"\${arr[*]-}\"）："
  printf '      %s\n' "$unsafe_expand" >&2
else
  ok "无 set -u 下的空数组裸展开（bash 4.2 兼容，含 [@] 与 [*] 两种下标）"
fi

if [[ $fail -ne 0 ]]; then
  echo "check-invariants: FAILED" >&2
  exit 1
fi
echo "check-invariants: OK"
