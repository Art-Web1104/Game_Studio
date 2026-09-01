# R2-RNG-0001 게이트 위반 기록과 회수 절차

- 작성일: `2026-09-01`
- 작업: `R2-RNG-0001`
- 위험 등급: `HIGH`
- 상태: `RECOVERED_UNDER_CONTRACT`
- 감사 이벤트: `audit/events/R2-RNG-0001-events.json`

## 1. 무엇이 위반되었는가

이전 세션은 `READY` 상태의 Task Contract 없이 `studio_core/rng.py` 구현을 시작했다.

| 항목 | 내용 |
| --- | --- |
| 위반 규칙 | `CLAUDE.md` Required workflow 2항 "Reject work whose task status is not `READY` or `IN_PROGRESS`" |
| 함께 위반된 규칙 | `AGENTS.md` Mandatory workflow 1항, Authority order 4항 (Task Contract 선행) |
| 위반 결과물 | 미추적(untracked) 파일 `studio_core/rng.py` 1개 |
| 위반 시점 상태 | 해당 작업에 대응하는 `tasks/*.json`, `artifacts/*.json`, `handoffs/*.json` 부재 |
| 발견 경위 | 후속 세션에서 `git status`에 미추적 파일만 존재하고 대응 Task Contract가 없음을 확인 |

RNG는 `AGENTS.md`가 `High` 위험으로 분류하도록 명시한 영역이다. 계약 없이 시작된 High 위험
구현은 승인자·예산·롤백·수용 기준이 정의되지 않은 상태의 작업이므로, 결과물의 품질과 무관하게
절차상 무효다.

## 2. 무엇이 위반되지 않았는가

사실 관계를 정확히 남긴다. 아래 항목은 점검했고 위반이 없었다.

- 커밋과 푸시가 수행되지 않았다. 위반은 작업 트리에만 존재했고 이력에 들어가지 않았다.
- 기본 브랜치가 아니라 `feat/r2-csprng-baseline` 브랜치에서 발생했다.
- 초안에 평문 비밀값, API 키, 토큰, 개인정보가 포함되지 않았다.
- 기존 승인 산출물(R0 기준선, R1 후보, `SYS-CLD-0011`)은 변경되지 않았다.
- 파괴적 Git·파일시스템 명령이 사용되지 않았다.

## 3. 회수 시점 원본 보존

초안은 삭제하거나 덮어쓰지 않고 먼저 측정·기록했다. 아래 값이 회수 시점의 원본 지문이다.

| 항목 | 값 |
| --- | --- |
| 경로 | `studio_core/rng.py` |
| 크기 | `27631` bytes |
| 줄 수 | `713` |
| sha256 | `aedfacb41a18e03756f21ddd3203df9f9b82abf4c73d1319b838bf44c78d8591` |
| Git 상태 | untracked (`??`), 기준 커밋 `06331a4` |

이 지문은 `tasks/R2-RNG-0001.json`의 `inputs[]`에 `recovered://studio_core/rng.py@pre-task-draft`
버전 `0.1.0-draft`로 등록되어 있고, `audit/events/R2-RNG-0001-events.json`의
`AE-R2RNG-0002 UNTRACKED_DRAFT_PRESERVED` 이벤트 `resource_refs`에도 남아 있다. 초안은 이후
계약 아래에서 수정되므로 파일의 현재 해시는 이 값과 다르며, 그 차이는 의도된 것이다.

## 4. 회수 절차

계약을 소급 정당화하는 것이 아니라, 위반 사실을 남긴 채로 이후 작업만 계약 아래로 들여왔다.

1. 초안을 읽고 지문을 측정해 보존했다. 추가 구현은 중단한 상태로 유지했다.
2. `tasks/R2-RNG-0001.json`을 `READY`, `HIGH`, owner `A-20`, 승인자 `A-50`·`A-02`·`A-00`·`USER`,
   예산 `USD 20 / 10800초 / stop_on_limit`, 롤백, `INTERNAL`·비개인정보·`REFERENCE_ONLY`로 작성했다.
3. Task Contract를 `contracts/task.schema.json`에 직접 검증하고 상태가 `READY`임을 확인했다.
   `studio_core.collaboration.evaluate_delegation`의 위임 게이트도 `DELEGATED`로 통과했다.
4. 착수 시점 `artifacts/R2-RNG-0001-artifact.json`(`DRAFT`)과
   `handoffs/R2-RNG-0001-handoff.json`(`BLOCKED`, 표준 명령 `NOT_RUN`)을 생성했다.
5. 그 상태에서 전체 기준선을 실행했다. 예상대로 실패했고, 실패 사유는
   `R2-RNG-0001: handoff is not independently verifiable: unsupported readiness 'BLOCKED'`였다.
   검증기가 미완료 작업을 통과시키지 않는다는 것이 이 실행의 증거다.
6. 이후에만 구현·테스트·검증기 통합·문서 작업을 재개했다.

## 5. 회수 이전 상태로의 완전 롤백

`studio_core/rng.py`는 미추적 파일이므로 커밋 이력에 복원 대상이 없다. 따라서 완전 롤백은
"초안 이전"이 아니라 "위반 이전", 즉 커밋 `06331a4` 상태로의 복귀를 뜻한다. 어떤 경로에서도
파괴적 Git·파일시스템 명령을 사용하지 않으며, 되돌리는 대상은 삭제가 아니라 보존·격리한다.

### 5.1 롤백 대상 목록

신규 파일 18개.

| # | 경로 |
| --- | --- |
| 1 | `.gitattributes` |
| 2 | `tasks/R2-RNG-0001.json` |
| 3 | `artifacts/R2-RNG-0001-artifact.json` |
| 4 | `handoffs/R2-RNG-0001-handoff.json` |
| 5 | `studio_core/rng.py` |
| 6 | `studio_core/rng_stats.py` |
| 7 | `studio_core/integrity.py` |
| 8 | `games/roulette/rng-draw-record.schema.json` |
| 9 | `games/roulette/fixtures/rng-draw-record.example.json` |
| 10 | `tests/test_rng.py` |
| 11 | `tests/test_integrity.py` |
| 12 | `audit/events/R2-RNG-0001-events.json` |
| 13 | `docs/games/R2-rng-csprng.md` |
| 14 | `docs/operations/R2-RNG-0001-recovery.md` |
| 15 | `docs/operations/R2-followup-units.md` |
| 16 | `docs/status/R2-STATUS.md` |
| 17 | `docs/approvals/R1-evidence-closure.md` |
| 18 | `docs/approvals/R2-RNG-0001-validation-report.md` |

수정 파일 4개.

| # | 경로 |
| --- | --- |
| 1 | `scripts/validate_baseline.py` |
| 2 | `studio_core/__init__.py` |
| 3 | `docs/approvals/R1-checklist.md` |
| 4 | `docs/status/R1-MOBILE-STATUS.md` |

### 5.2 경로 A — 이 작업의 PR 커밋이 이미 존재하는 경우

1. 되돌릴 커밋 해시를 정확히 특정한다.
2. `git revert <commit>`으로 되돌림 커밋을 만든다. 되돌림 사실이 이력에 남는다.
3. 이력 재작성, 강제 푸시, 브랜치 삭제는 하지 않는다.

### 5.3 경로 B — 커밋 이전, 변경이 작업 트리에만 있는 경우

1. 현재 소스를 먼저 보존한다. 5.1의 22개 경로 전체를
   `quarantine/R2-RNG-0001/<UTC-timestamp>/` 아래에 원본 그대로 복사한다.
2. 수정 파일 4개는 `git diff 06331a4 -- <경로>`로 역패치 후보를 만들고, 사람이 그 패치 내용을
   검토한 뒤 `git apply --reverse`로 적용해 `06331a4` 상태로 복원한다. 검토 없이 작업 트리를
   덮어쓰는 명령은 사용하지 않는다.
3. 신규 파일 18개는 삭제하지 않고 1단계에서 만든 같은 quarantine 디렉터리로 이동한다.

### 5.4 두 경로 공통 마무리

1. `python scripts/validate_baseline.py`를 실행한다.
2. `python -m unittest discover -s tests -v`를 실행한다.
3. R1 기준선이 그대로 통과하는지 확인한다. 작업 트리 상태 확인은 quarantine 경로를 제외하고
   판정하며, quarantine 사본은 이 회수 기록이 갱신될 때까지 증거로 보존한다.

`studio_core/rng.py`의 회수 시점 sha256과 규모는 3절에 보존되어 있으므로, 격리 이후에도 초안
지문은 확인 가능하다.

### 5.5 커밋 권한

Claude는 커밋과 푸시를 수행하지 않으며 이 작업의 산출물은 작업 트리 변경으로만 남긴다.
독립 검증을 마친 뒤 사용자의 상시 승인 아래 커밋과 PR 개설을 수행할 수 있는 주체는 Codex다.
그 커밋이 존재하는 시점부터 롤백은 경로 B가 아니라 경로 A를 따른다.

## 6. 재발 방지

- `scripts/validate_baseline.py`의 `validate_collaboration`은 `tasks/` 아래 모든 Task Contract에
  대응하는 Artifact Contract와 Handoff Packet을 요구한다. 계약 없이 만들어진 구현은 이 검증을
  통과할 수 없고, 계약이 있어도 증거가 없으면 5단계에서 확인한 대로 실패한다.
- `validate_r2_rng`가 `audit/events/R2-RNG-0001-events.json`에 위반·보존·발행·회수 4개 이벤트가
  해시 연결된 상태로 남아 있는지 검사한다. 기록을 지우면 기준선이 실패한다.
- 남은 공백은 도구가 아니라 절차다. 구현 착수 전에 `tasks/`에 대응 계약이 있는지 확인하는 것은
  여전히 실행자의 책임이며, 이 문서가 그 책임의 근거 기록이다.
