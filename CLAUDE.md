# Clawket Plugin (`clawket/`)

Claude Code 플러그인 셸. 훅 어댑터, install gate, 플러그인 manifest, skills, 프로젝트
범용 문서를 번들한다. **CLI / daemon / web 소스를 포함하지 않는다** — 이들은 install
gate 가 `components.json` 의 핀에 따라 GitHub Releases 에서 바이너리/번들로 끌어온다.

본 sub-repo 만 clone 되어 sibling (`cli/`, `daemon/`, `web/`) 소스가 없는 상태에서도
이 문서만으로 유지보수가 가능해야 한다. 본 sub-repo (`github.com/clawket/clawket`)
는 cross-repo 좌표의 정본 보유자다 — 컴포넌트 핀은 `components.json`, 호환성
매트릭스는 `docs/COMPATIBILITY.md`, 릴리즈 order 는 `docs/RELEASING.md`. 다른 sub-repo
의 CLAUDE.md 는 이 위치들을 가리킨다.

## Stack & 진입점

| 항목 | 값 |
|---|---|
| Stack | Node 20+ (CommonJS `.cjs`), zero runtime deps (dependencies 없음) |
| 패키지 | `package.json` — `name: "clawket-plugin"`, scripts: `setup` / `dev:fresh-install` / `test` (플러그인 버전은 `package.json#version` 정본) |
| 플러그인 ID | `clawket` (`.claude-plugin/plugin.json`); 버전은 `plugin.json#version` 정본 |
| MCP 등록 | `.mcp.json` → stdio `clawket mcp` (CLI 바이너리에 내장된 rmcp 1.5 서버) |
| Compat 범위 | 컴포넌트별 SemVer 범위 — 정본 `compat.json` (현재 cli/daemon `>=0.2.0 <1.0.0`, web `>=0.1.0 <2.0.0`, desktop `>=3.0.0 <4.0.0`) |
| 컴포넌트 핀 | `components.json` 이 정본 (정확한 cli/daemon/web 핀은 직접 참조). `desktop = null` sentinel — `clawket/desktop` 첫 릴리즈 전까지 no-op skip |
| Clawket 프로젝트 | `PROJ-lattice-mono` (key `LM`) — wrapper 와 모든 sub-repo 공유 |

## Hook 라우팅 (`hooks/hooks.json`)

6 표준 Claude Code 이벤트 + `PostToolUse` 의 `ExitPlanMode` matcher 분기. 각 어댑터
(`adapters/claude/*.cjs`)는 2-줄 shim 으로 `adapters/shared/claude-hooks.cjs` 의
헬퍼에 위임한다.

| 이벤트 | matcher | 핸들러 (`adapters/claude/`) | 위임 함수 |
|---|---|---|---|
| `SessionStart` | `startup\|clear\|compact` | `session-start.cjs` | `runSessionStart` — install gate 호출, 데몬 기동, 대시보드/룰 주입 |
| `UserPromptSubmit` | (all) | `user-prompt-submit.cjs` | `runUserPromptSubmit` — 활성 태스크 컨텍스트 주입, 미설정 시 경고 |
| `PreToolUse` | `Agent\|TeamCreate\|SendMessage\|Edit\|Write\|Bash` | `pre-tool-use.cjs` | `runPreToolUse` — 활성 태스크 게이트 + destructive 패턴 hard-block + PDD X3/X7/X8/X9 |
| `PostToolUse` | `Edit\|Write` | `post-tool-use.cjs` | `runPostToolUse` — 파일 변경을 활성 태스크에 기록 + X3 |
| `PostToolUse` | `ExitPlanMode` | `plan-sync.cjs` | `runPlanSync` — Plan Mode 출력을 Clawket plan 으로 등록 prompt (Claude Code 가 `ExitPlanMode` 를 hook event 가 아닌 Tool 로 분류) |
| `SubagentStart` | (all) | `subagent-start.cjs` | `runSubagentStart` — sub-agent 를 태스크에 바인딩 + X3/X7/X9 |
| `SubagentStop` | (all) | `subagent-stop.cjs` | `runSubagentStop` — 결과 요약 append + X8 evidence 검증 + 자동 완료 |

`adapters/claude/` 의 그 외 파일 (`stop.cjs`, `setup.cjs`, `task-{created,completed}.cjs`)
은 manifest 에 라우팅되지 않은 보조 진입점이다 (수동/CI/내부 호출용). `hooks/hooks.json`
이 actual 라우팅의 정본.

## Install gate — `ensureInstalled`

**`adapters/shared/claude-hooks.cjs:1067`** 의 `ensureInstalled(pluginRoot)` 가 유일한
install 로직. 어떤 새 코드 경로에서도 이 함수를 우회해 별도 install 절차를 만들지
않는다. 동작:

1. `components.json` 매니페스트 로드 (실패 시 stderr 경고 + `false`).
2. Fast-path 검사 — `bin/clawket`, `daemon/bin/clawketd`, `web/dist/index.html`,
   `desktop/dl/<artifact>` 의 존재 + `.clawket-version` 마커가 핀된 버전과
   일치하는지 + 7 skill 무결성 (`verifySkills`). 모두 OK 면 즉시
   `true`. 단, `components.json#desktop` 이 `null` (sentinel — desktop
   sub-repo / first release 미배포) 일 때는 desktop 체크가 항상 통과한다.
3. 그렇지 않으면 `withInstallLock(() => runSetup())` — `runSetup` 은
   `ensureCliBinary` / `ensureDaemonBinary` / `ensureWebBundle` /
   `ensureDesktopBundle` 순서로 GitHub Releases 에서 받아 `pluginRoot` 아래에
   푼다 (`adapters/shared/claude-hooks.cjs:2761`). `ensureDesktopBundle` 은
   `null` 핀을 no-op 으로 skip 하므로 desktop 핀이 `null` 인 동안에는 실제 다운로드가 일어나지
   않는다.
4. Post-install 검증 — 데몬을 띄우고 `/health` ping. 실패 시 daemon 마커를 무효화해
   다음 세션이 재시도하도록 만들고 `false` 반환.

진입점:
- 자동: `adapters/claude/session-start.cjs` 첫 줄의 `runSessionStart()` 가
  `ensureInstalled` 를 호출 (`adapters/shared/claude-hooks.cjs:1614`).
- 수동/CI: `pnpm run setup` → `scripts/setup.cjs` → `adapters/claude/setup.cjs` →
  `runSetup()` (gate 의 download 단계만 직접 호출).

## 경로 분리 invariant (LM-8)

플러그인이 쓰는 파일은 **`pluginRoot` 하위에만** 존재해야 한다. 사용자 데이터는
별도 XDG 경로에 있으며 플러그인 코드 어디서도 write 대상이 되지 않는다.

| 영역 | 용도 | 재설치 시 |
|---|---|---|
| `~/.claude/plugins/clawket-*/bin/clawket` | CLI 바이너리 | 삭제 → 재다운로드 |
| `~/.claude/plugins/clawket-*/daemon/bin/clawketd` | 데몬 바이너리 | 삭제 → 재다운로드 |
| `~/.claude/plugins/clawket-*/web/dist/` | 웹 번들 | 삭제 → 재다운로드 |
| `~/.claude/plugins/clawket-*/desktop/dl/` | Tauri 데스크톱 installer (.dmg/.msi/.AppImage); `null` 핀일 때 비어있음 | 삭제 → 재다운로드 (또는 null skip) |
| `~/.local/share/clawket/` (SQLite 등) | 사용자 데이터 | **보존** |
| `~/.cache/clawket/` (socket / pid / port) | 캐시 | **보존** |
| `~/.config/clawket/` | 설정 | **보존** |
| `~/.local/state/clawket/` (hook.log 등) | 상태/감사 | **보존** |

강제 메커니즘 (2단계):
1. Runtime — daemon 의 `paths::ensure_no_plugin_overlap` 이 기동 시 다섯 경로
   (data/cache/config/state/db) 모두를 검사하고 overlap 발견 시 기동 거부.
   `CLAWKET_ALLOW_PLUGIN_OVERLAP=1` 만 우회 가능 (데이터 손실 위험 인지 의미).
2. 진단 — `clawket doctor` 의 `[Path separation invariant (LM-8)]` 섹션이 같은
   다섯 경로를 검사해 위반 시 exit code 1. `tests/path-separation.e2e.test.cjs`
   가 CI 에서 회귀를 잡는다.

플러그인 코드 어디서도 사용자 데이터 경로에 write 하지 않는다 — install gate 도
`pluginRoot` 만 만진다. 새 코드 경로 추가 시 이 경계를 깨면 invariant 검사가
즉시 잡는다.

## 컴포넌트 핀 계약

`components.json` 은 cross-repo 버전 핀의 정본. 핀을 bump 하면 다음 SessionStart
에서 `ensureInstalled` 가 mismatch 를 감지하고 자동으로 새 바이너리를 받는다.

**단, 사용자가 보는 것은 `main` 의 `components.json` 이 아니라 설치된 플러그인
릴리즈 안의 사본이다.** 핀 bump PR 은 `chore:` 로 자동 생성되고 `chore:` 는
release.yml 이 릴리즈로 인정하지 않으므로, 그 PR 을 머지하는 것만으로는
사용자 환경에 아무것도 도달하지 않는다. 실제로 그런 일이 있었다 — daemon
v0.5.0 과 cli v0.6.2 를 배포하고 두 핀 PR 을 머지했는데, 세 config 폴더 모두
여전히 v0.4.1 / v0.6.1 을 쓰고 있었다.

그러므로 컴포넌트 배포는 **플러그인 릴리즈까지가 한 단위**다. 핀 PR 머지 후
`fix:` 커밋으로 플러그인 patch 를 내야 install gate 가 새 바이너리를 받는다.

핀 변경 체크리스트:
1. 대상 컴포넌트의 GitHub Release 가 `@clawket/{cli,daemon,web}` 에 실제로
   존재하는지 확인.
2. 조합이 `docs/COMPATIBILITY.md` 의 호환성 매트릭스 안에 있는지 확인.
3. 매트릭스를 벗어나는 변경이면 플러그인 자체의 major bump 가 동반되어야 한다
   (`package.json#version` + `.claude-plugin/plugin.json#version`).
4. 릴리즈 순서 (daemon → cli → web → plugin) 는 `docs/RELEASING.md` 정본.

## Skills (`skills/*`)

`.claude-plugin/plugin.json#skillsList` 에 7개 등록. 각 skill 은 `skills/<name>/SKILL.md`
와 동반 `RULE.md` 로 구성되고, install gate 의 `verifySkills` 가 14 파일 (7 × 2) 무결성을 검사한다.

| Skill | 진입점 | 역할 |
|---|---|---|
| `clawket-dashboard` | `/clawket-dashboard` | task/plan/unit/cycle 조회·갱신 + `start`/`done`/`new` 라이프사이클 게이트 |
| `clawket-plan-design` | `/clawket-plan-design` | Plan + Unit 사전 설계 (Done 명제, 분해, 의존성 그래프, 수렴 조건) |
| `clawket-scenario-author` | `/clawket-scenario-author` | atomic Given/When/Then 시나리오 작성 (도메인별 spec knowledge) |
| `clawket-verify-batch` | `/clawket-verify-batch` | Sub-agent batch dispatch + TSV evidence + bulk sync transcription |
| `clawket-verify-loop` | `/clawket-verify-loop` | 검증 라운드 러너 (Round R 디스패치 + 3-way 수렴 + 회귀 감지) |
| `clawket-scenario-refine` | `/clawket-scenario-refine` | scenario_error 3-way 처리 (atomic 분해 / 의도 재정의 / 삭제) |
| `clawket-defect-fix` | `/clawket-defect-fix` | defect → fix task 등록 + 코드 수정 |

## 문서 라우팅 (`docs/`)

| 알고 싶은 것 | 정본 |
|---|---|
| 호환성 매트릭스 (plugin × cli × daemon × web) | `docs/COMPATIBILITY.md` |
| 릴리즈 순서·체크리스트·태그 규칙 | `docs/RELEASING.md` |
| Hook MCP enforcement 설계 | `docs/HOOK_ENFORCEMENT.md` |
| i18n / 번역 drift 정책 | `docs/i18n-policy.md` |
| 기여 워크플로 (decompose / contract / execute) | `docs/CONTRIBUTING.md` (cross-repo 정본) |
| GitHub label 정의 | `docs/labels.md` |
| End-user 설치·기능 | `README.md`, `README.ko.md` |
| 어댑터 내부 (hook 라우팅 + destructive guardrail) | `adapters/claude/README.md` |

## Build / Verify

```bash
node --version                # 20+ 필요
pnpm install                  # 개발 의존성 설치 (husky 만; runtime deps 는 zero)
pnpm test                     # node --test tests/*.test.cjs
pnpm run setup                # ensureInstalled 수동 트리거 (현재 cwd 와 무관)
pnpm run dev:fresh-install    # 핀된 바이너리 클린 재설치 (개발 루프)
```

**패키지 매니저** — `packageManager: "pnpm@10.x"` 가 `package.json` 에 핀되어 있고 `package-lock.json` / `yarn.lock` 은 `.gitignore` 로 차단된다. 기여자는 `corepack enable` 또는 동일 메이저의 pnpm 을 사용한다 (npm install 은 husky `prepare` 만 실행해 동작하지만, 다른 lockfile 을 만들면 안 된다).

테스트 스위트 (`tests/*.test.cjs`) 는 install/hook 게이트의 회귀를 잡는다 —
`destructive-patterns`, `disabled-project-bypass`, `exit-plan-mode-strict`,
`path-separation.e2e`, `plugin-reinstall.e2e`, `pre-tool-use.e2e`, `skills-integrity`,
`data-loss-diagnostics.e2e`.

## AI 가드레일

- **커밋/푸시 금지** — 사용자 명시 지시 전까지 commit/push 금지 (wrapper 룰 상속).
- **Install gate 단일화** — `ensureInstalled` 외에 install 경로를 만들지 않는다.
  새 진입점(setup shim, CI script 등)을 추가하려면 같은 함수를 호출하도록 위임.
- **LM-8 경계** — 플러그인 코드 어디서도 `~/.local/share/clawket/`, `~/.cache/clawket/`,
  `~/.config/clawket/`, `~/.local/state/clawket/` 에 write 하지 않는다. 사용자 상태는
  데몬이 소유한다. write 가 필요하면 daemon HTTP/MCP 를 경유한다.
- **Hook 우회 금지** — `PreToolUse` 의 활성 태스크 게이트 / destructive guard /
  PDD X3·X7·X8·X9 enforcement 는 의도된 설계다. matcher 를 좁히거나 핸들러를
  비우는 변경은 사용자 명시 승인 필요. `CLAWKET_BYPASS_HOOKS=1` 은 개발 루프용
  escape valve 이며 routine 작업에 사용하지 않는다.
- **컴포넌트 핀 bump** — `components.json` 수정은 단독 PR. 동반 변경:
  ① `docs/COMPATIBILITY.md` 매트릭스 갱신, ② major bump 필요성 판단,
  ③ GitHub Release 존재 확인. 셋 모두 만족 못 하면 bump 보류.
- **2-줄 shim 룰** — `adapters/claude/*.cjs` 는 shared 헬퍼에 위임하는 thin shim
  이다. 비즈니스 로직을 shim 에 직접 넣지 않는다 — `adapters/shared/claude-hooks.cjs`
  로 이동 후 export.
- **활성 태스크 없이 변경 금지** — Clawket 자체의 hook 가 본 sub-repo cwd 에서도
  동작한다. 작업 전 활성 태스크 지정 (`clawket dashboard --cwd .`).
