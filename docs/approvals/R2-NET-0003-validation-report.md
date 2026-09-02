# R2-NET-0003 검증 보고서

- 작업: `tasks/R2-NET-0003.json` (`READY`, 소유자 `A-02`, 위험 `HIGH`)
- 계약: `games/roulette/reconnect-contract.yaml`
- 설계 문서: `docs/games/R2-reconnect-continuity.md`
- 감사 기록: `audit/events/R2-NET-0003-events.json`
- 작성자: `A-02` (구현자). **이 문서는 구현자의 자체 점검 기록이며 승인이 아니다.**

## 1. 무엇을 주장하고 무엇을 주장하지 않는가

주장한다: 아래 명령과 시험이 이 작업 트리에서 실제로 실행되어 통과했다.

주장하지 않는다: 독립 검증, 인간 최종 승인, `A-50`/`USER` 게이트 판정, 호스티드 CI 관측,
운영 준비 완료, `R5` 일정. 이 여섯 가지는 모두 `NOT_RUN`이다.

## 2. 실행한 명령

| 명령 | 결과 |
| --- | --- |
| `python scripts/validate_baseline.py` | PASS (exit 0, 20단계) |
| `python -m unittest discover -s tests -v` | PASS (608 tests, OK, skipped=4) |
| `python -m unittest tests.test_reconnect_continuity` | PASS (29 tests) |
| `python -m compileall -q apps scripts studio_core tests` | PASS |
| `python scripts/scan_secrets.py` | PASS (평문 비밀값 0건) |
| `python -m unittest tests.test_reconnect_continuity` (반복 3회) | PASS (29 tests, 3회 동일) |

### 2.1 구현 중 드러난 선언되지 않은 무결성 연쇄 — 중단 후 승인받아 해소

`apps/roulette_web/static/app.js`는 이 계약이 승인한 산출물이다. 그런데 그 파일을 고정하는
참조가 하나 더 있다. `artifacts/R4-UI-0006-artifact.json`의 `specification`에 있는
`component_hash:apps/roulette_web/static/app.js` 키다.

계약 개정 당시의 역방향 참조 추적은 `inputs[].uri`와 `artifact.uri`만 훑었고 이 종류의 참조를
보지 않았다. 그래서 이 파일은 계약의 산출물로 선언되지 않았다.

폐포를 다시, 이번에는 `component_hash` 키까지 포함해 계산한 결과는 다음과 같다.

```
apps/roulette_web/static/app.js
  -> artifacts/R4-UI-0006-artifact.json   [component_hash]
       -> tasks/SYS-QA-0015.json          [input]
            -> (끝)
```

`tasks/R4-ART-0007.json`에는 **도달하지 않는다.** 필요한 최소 수정은 두 줄이다.

1. `artifacts/R4-UI-0006-artifact.json`의 `component_hash:apps/roulette_web/static/app.js`
2. `tasks/SYS-QA-0015.json`의 `inputs[repo://artifacts/R4-UI-0006-artifact.json].content_hash`

지시는 "선언되지 않은 경로나 새 무결성 연쇄를 만나면 범위를 넓히지 말고 중단하라"였다. 1차
시도가 바로 그 규칙을 어겨 폐기됐으므로, 이번에는 **고치지 않고 멈춰서 보고했다.**

Codex는 이후 `REWORK` 승인으로 그 두 줄을 명시 승인했고, 승인 이후에만 수정했다. 수정 범위는
`artifacts/R4-UI-0006-artifact.json` `+1/-1`, `tasks/SYS-QA-0015.json` 해시 두 줄
(`validate_baseline.py` 재고정과 이번 아티팩트 재고정)이다. `artifacts/R4-UI-0006-artifact.json`은
이제 이 계약의 산출물로 선언되어 있으므로 수정된 파일 중 미선언 경로는 없다.

`component_hash` 키까지 포함해 폐포를 다시 계산한 결과, 변경 집합 10건이 모두 종단이고 추가로
요구되는 파일이 없으며 `tasks/R4-ART-0007.json`에 도달하지 않는다.

`AC-010`의 문언은 이후 승인 아래 개정되어 이 네 파일 폐포를 그대로 열거한다(4.1절). 남는 편차는
없다.

## 3. 수용 기준별 증거

| 기준 | 증거 | 결과 |
| --- | --- | --- |
| AC-001 재수화가 서버 권위 상태만 | `RehydrationTests.test_reconnect_snapshot_matches_the_durable_store`, `..._after_restart_is_rebuilt_from_durable_state` | PASS |
| AC-002 OPEN 이탈 후 베팅 부활 금지 | `BettingResurrectionTests` 3건 | PASS |
| AC-003 유실 응답 재시도가 이중 추첨·엔트로피·지급 없음 | `LostSettlementResponseTests` 5건 (실제 소켓 단절) | PASS |
| AC-004 커밋된 결과가 스냅샷으로 관측 가능 | `test_recent_results_match_the_audit_chain_after_restart` | PASS |
| AC-005 클라이언트 무권위 | `ClientAuthorityTests` 2건 + `validate_r2_reconnect` 정적 검사 | PASS |
| AC-006 결정론적 로컬 HTTP 시험 | `test_recovery_is_stable_under_repetition`, 모듈 3회 반복 실행 | PASS |
| AC-007 운영 경계 보존 | `ChangeShapeTests.test_no_new_route_was_added`, `validate_r4_playable_slice` | PASS |
| AC-008 새 경로·모듈·API 없음 | `test_no_new_route_was_added`, `test_no_new_runtime_module_was_added` | PASS |
| AC-009 동결 경로 무결성 | `test_frozen_paths_still_match_their_declared_hashes` (9경로) | PASS |
| AC-010 메타데이터 폐포 4파일 한정 | `test_repin_scope_is_exactly_the_declared_contracts` + diff 검토 | PASS |
| AC-011 계약↔구현 대조 + 네거티브 | `validate_r2_reconnect` + `ReconnectValidatorNegativeTests` 12건 | PASS |
| AC-012 두 표준 명령 + 비밀값 스캔 | 2절 | PASS |
| AC-013 범위 밖 미수행 | `reconnect-contract.yaml` `out_of_scope`, 변경 경로 목록 | PASS |
| AC-014 중단된 1차 시도 감사 보존 | `audit/events/R2-NET-0003-events.json` 3번 이벤트, `validate_r2_reconnect` | PASS |

## 4. 시험이 계약을 고친 곳 — 승인된 명확화

계약 초안은 재시작 이후의 거절 코드를 `REQUEST_ID_ALREADY_USED` 하나로 적었다. 시험이 실제로
관측한 것은 달랐다. 구현자는 문언을 임의로 고치지 않고 편차로 보고했고, Codex가 명확화를 승인한
뒤에 반영했다. 아래는 관측 사실이고, 현재 `AC-003`의 문언은 이 사실과 일치한다.

1. **`NO_BETS`** — 재시작한 서버는 빈 라운드를 연다. `RouletteTable.spin`의 베팅 존재 검사가
   내구 저장소보다 먼저 걸린다.
2. **`DRAW_DENIED`** — 새 라운드에 베팅이 있으면 저장소까지 간다. 그런데 라운드 식별자가
   인스턴스 토큰을 담으므로 재시도는 항상 다른 `round_id`를 들고 오고, 저장소는 같은
   `request_id`의 다른 요청 지문을 `DUPLICATE_REQUEST_CONFLICT`로 거절한다.
3. **`REQUEST_ID_ALREADY_USED`는 재시작 경로에서 도달하지 않는다.** 같은 `round_id`로
   재제출되어야 도달하는데 그런 일이 생기지 않는다. 계약은 이 코드를 재시작 거절 코드 목록에서
   빼고 `store_replay_reachable_after_restart: false`로 따로 기록한다. 검증기는 이 코드가
   재시작 목록에 다시 들어오면 실패한다.

세 경우 모두 **실패 폐쇄**이며 안전 속성(두 번째 추첨·엔트로피 소비·정산·잔액 이동 없음)은
동일하다. 계측으로 확인했다: `draw_record` 건수, `ledger_transaction` 건수, 플레이어 잔액,
`DeterministicTestEntropySource.consumed` 네 값이 복구 전후로 변하지 않는다.

### 4.1 승인된 계약 명확화 두 건

미해결 수용 기준 편차는 **0건**이다. 두 건 모두 보고 → 승인 → 반영 순서를 거쳤고,
`audit/events/R2-NET-0003-events.json`의 `TASK_CONTRACT_CLARIFIED_BY_APPROVAL` 이벤트로 남는다.

**`AC-003`** — 재시작 경로에서 도달하지 않는 `REQUEST_ID_ALREADY_USED` 요구를 제거하고, 실제로
도달 가능한 `NO_BETS`와 `DRAW_DENIED`를 기술한다. 안전 속성 문언(두 번째 추첨·엔트로피 소비·
원장 거래·지급·잔액 변동 없음)은 그대로이고, 커밋된 결과가 `recent_results`로 계속 관측 가능해야
한다는 요구가 명시됐다.

**`AC-010`** — 재고정 범위를 계약 3건에서 승인된 네 파일 메타데이터 폐포로 넓힌다. 열거된 항목은
`SYS-AST-0014`의 검증기 입력 해시, `SYS-CI-0012`의 검증기 입력 해시, `SYS-QA-0015`의 검증기 입력
해시와 R4 UI 아티팩트 입력 해시, `artifacts/R4-UI-0006-artifact.json`의 app.js `component_hash`
다섯 개 필드(파일 기준 네 건)이며, 전부 해시 값만 바꿀 수 있고 다른 필드 변경은 금지된다.

구현자가 자기 구현에 맞춰 문언을 고친 것이 아니다. 두 번 다 멈추고 보고했으며, 그 사실과 1차
시도 폐기 사실은 계약·아티팩트·핸드오프·감사 기록에 그대로 남아 있다.

## 5. 변경한 경로

**신규 5건**: `games/roulette/reconnect-contract.yaml`, `tests/test_reconnect_continuity.py`,
`docs/games/R2-reconnect-continuity.md`, `audit/events/R2-NET-0003-events.json`,
`docs/approvals/R2-NET-0003-validation-report.md`

**수정 4건**: `apps/roulette_web/static/app.js`, `scripts/validate_baseline.py`,
`docs/operations/R2-followup-units.md`, `tasks/R2-NET-0003.json`

**해시 재고정 4건**: `tasks/SYS-AST-0014.json`, `tasks/SYS-CI-0012.json`, `tasks/SYS-QA-0015.json`
(`scripts/validate_baseline.py` 해시), 그리고 Codex `REWORK` 승인으로 추가된
`artifacts/R4-UI-0006-artifact.json`(`component_hash:apps/roulette_web/static/app.js`)와
`tasks/SYS-QA-0015.json`의 그 아티팩트 입력 해시

**계약 3종**: `tasks/R2-NET-0003.json`, `artifacts/R2-NET-0003-artifact.json`,
`handoffs/R2-NET-0003-handoff.json`

**무변경 9건**(동결, 해시 대조로 확인): `apps/roulette_web/server.py`,
`apps/roulette_web/table.py`, `games/roulette/playable-slice-contract.yaml`,
`docs/status/R2-STATUS.md`, `apps/roulette_web/static/index.html`,
`apps/roulette_web/static/styles.css`, `tests/test_roulette_web_server.py`,
`tests/test_roulette_web_ui.py`, `tasks/R4-ART-0007.json`

`R4-ART-0007`과 그 자산·이미지 산출물은 어떤 방식으로도 접근하지 않았다.

## 6. 남은 결함과 위험

- 절차적 교훈: 역방향 해시 참조 추적이 `specification`의 `component_hash` 키를 보지 않아 2차 연쇄를
  구현 중에야 발견했다. 향후 계약 발행은 이 참조 종류를 포함해야 하며, 도구화 여부는 계약의
  `open_decisions`에 열려 있다.
- 재시작 이후 **베팅별 내역은 복구되지 않는다.** 열린 라운드의 베팅이 내구화되어 있지 않기
  때문이다. 포켓·색·증명 해시·정산 시각·권위 잔액은 복구된다. 확장은 `R2-DBC-0002` 스키마
  결정에 종속되며 계약의 `open_decisions`에 남아 있다.
- `tasks/R2-NET-0003.json`이 `docs/operations/R2-followup-units.md`를 입력으로 고정하면서
  동시에 산출물로 선언한다. 그 문서를 갱신하면 자기 자신의 입력 해시를 갱신해야 하며, 이번에
  그렇게 했다. 계약의 잔여 결함이며 독립 검증에서 판단이 필요하다.
- `docs/status/R2-STATUS.md`는 `R4-ART-0007`로 이어지는 고정 사슬 때문에 갱신할 수 없었다.
  R2 상태 문서와 실제 진행 상태의 정합은 별도 유닛에서 처리해야 한다.
- 다른 유닛의 `READY` 계약 3건과 R4 UI 아티팩트 1건을 해시 재고정 목적으로 수정했다. 각 diff가
  `AC-010`이 열거한 해시 줄로만 이루어졌는지 독립 검증에서 확인해야 한다.
- 로컬 통과가 Linux 러너 통과를 보장하지 않는다. 호스티드 CI는 관측되지 않았다.

## 7. 인간 게이트

| 게이트 | 상태 |
| --- | --- |
| 독립 검증 (Codex 콘솔) | `NOT_RUN` |
| `A-20` 코드 검토 | `NOT_RUN` |
| `A-50` QA 판정 | `NOT_RUN` |
| `A-02` 승인 | `NOT_RUN` |
| `A-00` 승인 | `NOT_RUN` |
| `USER` 최종 승인 | `NOT_RUN` |
| 호스티드 CI 관측 | `NOT_RUN` |
| 커밋·푸시 | 수행하지 않음 |

`R5` 승인 이전이므로 상용 제작 일정과 출시일을 확정하지 않는다.
