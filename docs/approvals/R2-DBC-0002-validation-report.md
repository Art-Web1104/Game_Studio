# R2-DBC-0002 검증 보고서

- 작업: `R2-DBC-0002` 내구 상태 경계 (격리·원자성·동시성·장애 복구)
- 위험 등급: `HIGH`
- 작성 주체: Claude Code (구현자, `A-02` 대리)
- 작성일: `2026-09-01`
- 대상 산출물: `studio_core/durable_state.py`,
  `games/roulette/durable-state-contract.yaml`,
  `games/roulette/durable-state-schema.sql`, `tests/test_durable_state.py`,
  `scripts/validate_baseline.py::validate_r2_durable_state`,
  `docs/games/R2-durable-state.md`

## 0. 이 문서가 주장하지 않는 것

이 문서는 **게이트 판정이 아니다.** 구현자가 자신의 산출물에 대해 수행한 기계적 재실행의
기록이며, 독립 검토 서명도 최종 QA 승인도 아니다. `A-50`, `A-02`, `A-00`, `USER`의 판정은
9절에서 전부 미발행 상태다. 일정, 기간, 마감, 출시일도 정하지 않는다.

## 1. 검증 수행 주체와 분리

| 역할 | 주체 | 수행 |
| --- | --- | --- |
| 구현 | Claude Code (implementer 콘솔) | 코드·계약·스키마·시험·문서 작성 |
| 기계적 재실행 | 같은 콘솔 | 아래 3절의 명령 실행 |
| 독립 검토 | 미수행 | `code-reviewer` 서명 없음 |
| 최종 QA 게이트 | 미수행 | `A-50` 또는 `USER`만 발행 가능 |

`operations/collaboration.yaml`의 `separation_of_duties`는 `generator_is_reviewer`와
`self_approval`을 모두 `denied`로 고정한다. 3절의 `PASS`는 명령이 통과했다는 사실이지
승인이 아니다.

## 2. 검증 대상 범위

- 계약 선언과 구현 상수의 일치 (격리 수준, 트랜잭션 모드, WAL, `synchronous`, 외래키,
  busy 재시도, 스키마 버전, 경로 처리, 실패 동작, 금지 저장 필드)
- 발행된 SQL 스키마와 구현이 실행하는 문장의 일치
- 재시작 후 멱등성, 엔트로피 재소비 없음, 라운드당 단일 권위 결과·단일 정산
- 커밋 이전 모든 고장 지점의 완전 롤백
- 감사 이벤트의 전역 유일성, 데이터베이스 수준 추가 전용성, 재적재 후 체인 검증
- 정수 최소 단위 강제와 부동소수점 통화 거부
- 저장소 트리에 데이터베이스 파일이 남지 않음
- `studio_core/rng.py`가 이 유닛에서 수정되지 않았음 (Task Contract 입력 해시 대조)

## 3. 관측된 검증 결과

명령은 `2026-09-01` 기준 로컬 작업 트리(Windows, Python 3.12, 브랜치
`feat/r2-dbc-durable-state`)에서 실행했다.

| 검사 | 결과 | 관측 |
| --- | --- | --- |
| `python scripts/validate_baseline.py` | `PASS` | 전 단계 통과. `R2-DBC-0002 내구 상태 경계·격리 수준·원자성·동시성·장애 복구` 단계 포함 |
| `python -m unittest discover -s tests -v` | `PASS` | `Ran 353 tests`, 실패 0, 오류 0 |
| `python -m compileall -q studio_core scripts tests` | `PASS` | 구문 오류 없음 |
| `python scripts/scan_secrets.py` | `PASS` | 의도된 탐지기 픽스처 외 일치 없음 |
| 정규 LF/CRLF 무결성 대조 (`validate_content_integrity`) | `PASS` | 선언된 모든 `content_hash`가 정규 표현과 일치 |
| 호스팅 CI (`.github/workflows/ci.yml`) | `NOT_RUN` | 커밋·푸시를 수행하지 않았으므로 실행 이력이 없다 |
| 독립 코드 검토 (`code-reviewer`) | `NOT_RUN` | 이 세션에서 수행하지 않았다 |
| `A-50`/`A-02`/`A-00`/`USER` 게이트 | `NOT_RUN` | 9절 참조 |

`validate_r2_durable_state`가 선언 대조에 그치지 않고 실제로 관측한 것은 다음이다. 모두
임시 디렉터리의 일회용 데이터베이스에서 수행하고 정리했다.

- 첫 제출이 새 권위 결과를 커밋하고 정수 잔액을 `900 / 100`으로 이동시켰다.
- 저장소를 닫고 다시 연 뒤 같은 요청이 **엔트로피를 다시 읽지 않고** 원본 기록을 반환했고,
  `draw_record`와 `ledger_transaction`은 각각 1건으로 유지되었으며 잔액이 재이동하지 않았다.
- 재적재한 감사 체인이 검증되었고, `event_id`가 전역 유일했으며, 각 이벤트가
  `audit/audit-event.schema.json`을 만족하고 금지 필드와 평문 비밀값 규칙에 걸리지 않았다.
- 원시 SQL `UPDATE`와 `DELETE`가 `audit_event`에서 모두 거부되었다.
- 엔트로피원에 넣은 표지 바이트열이 데이터베이스 파일 안에 나타나지 않았다.
- 같은 `request_id`를 다른 매개변수로 재사용한 요청이 `DUPLICATE_REQUEST_CONFLICT`로 거부되었다.
- `after_begin`, `after_draw`, `after_ledger`, `before_commit` 네 고장 지점 각각에서
  커밋된 행 0건, 잔액 무변동, 추첨 감사 이벤트 없음, 체인 무결이 확인되었다.
- 미래 스키마 버전 파일이 `SCHEMA_VERSION_UNSUPPORTED`로 거부되었다.
- `:memory:`와 `file:...?mode=memory&cache=shared`가 `PATH_INVALID`로 거부되었다.

## 4. 계약·구현·문서 대조

| 대조 | 방법 | 결과 |
| --- | --- | --- |
| 계약 `storage` 블록 ↔ `contract_declaration()` | 전 키 동등 비교 | 일치 |
| 계약 `failure_behavior` ↔ `FAILURE_BEHAVIOR` | 전 키 동등 비교 | 일치 |
| 계약 `path_handling` ↔ `PATH_HANDLING` | 키별 비교 | 일치 |
| 발행 SQL ↔ `SCHEMA_STATEMENTS` | 문자열 동등 비교 | 일치 |
| `studio_core/rng.py` ↔ Task Contract 입력 해시 | 정규 LF 해시 대조 | 일치 (미수정) |
| Artifact 부품 해시 (`contract_hash`, `sql_schema_hash`, `test_suite_hash`) | 정규 LF 해시 대조 | 일치 |

부정 사례도 시험으로 존재한다. 계약이 `IMMEDIATE`를 `DEFERRED`로, `synchronous: full`을
`normal`로 잘못 적으면 거부되고, SQL이 표류하면 거부되며, `rng.py`가 수정되면 거부되고,
감사 체인이 변조되거나 필수 동작이 빠지면 거부되고, Artifact가 인간 승인을 참칭하거나 낡은
부품 해시를 들고 있으면 거부된다. 이 부정 사례들은 저장소 파일을 고치지 않고 격리된 사본에서
수행한다.

## 5. 미해결 위험

| 심각도 | 위험 |
| --- | --- |
| `HIGH` | 인간 게이트 미발행. `A-50`, `A-02`, `A-00`, `USER` 판정이 없다 |
| `HIGH` | 독립 코드 검토(`code-reviewer`) 미수행. 구현자의 자체 재실행만 있다 |
| `MEDIUM` | SQLite 단일 파일·단일 노드 참조 경계다. 다중 노드 운영 저장소의 격리·복제 특성은 증명되지 않았다 |
| `MEDIUM` | 동시성 증거는 로컬 스레드 실행이다. 실제 다중 프로세스·다중 호스트 경합은 후속 유닛의 대상이다 |
| `MEDIUM` | `synchronous=full` 선택의 쓰기 지연 비용을 측정하지 않았다. 측정은 `R2-LOAD-0004` 후보 범위다 |
| `LOW` | 감사 세그먼트 상한(`99 × 9999`) 소진 시 실패 폐쇄한다. 보존·회전 절차는 이 유닛 범위 밖이다 |
| `LOW` | 호스팅 CI 실행 이력이 없다. 커밋·푸시를 수행하지 않았기 때문이다 |

## 6. 범위 밖으로 이월된 항목

계약의 `out_of_scope`와 동일하며 `docs/operations/R2-followup-units.md`,
`docs/status/R2-STATUS.md`에 같은 식별자로 남아 있다.

- `R2-NET-0003` 실제 네트워크 재접속과 라운드 연속성 — `OPEN`
- `R2-LOAD-0004` 부하·성능 특성 — `OPEN`
- `R2-SEC-0005` 보안 침투 시험 — `OPEN`
- 외부 데이터베이스 서버 도입, 운영 배포, 백업·복구 절차, WAL 체크포인트 주기, 보존 기간
- 상용 제작 일정과 출시일 (`R5` 승인 이전 확정 금지)

## 7. 롤백 요약

이 작업은 커밋과 푸시를 수행하지 않았다. 변경은 작업 트리에만 있다.

- 추가된 파일: `studio_core/durable_state.py`, `games/roulette/durable-state-contract.yaml`,
  `games/roulette/durable-state-schema.sql`, `tests/test_durable_state.py`,
  `tasks/R2-DBC-0002.json`, `artifacts/R2-DBC-0002-artifact.json`,
  `handoffs/R2-DBC-0002-handoff.json`, `audit/events/R2-DBC-0002-events.json`,
  `docs/games/R2-durable-state.md`, `docs/approvals/R2-DBC-0002-validation-report.md`
- 변경된 파일: `scripts/validate_baseline.py` (필수 파일 목록과
  `validate_r2_durable_state` 단계 추가), `docs/status/R2-STATUS.md`,
  `docs/operations/R2-followup-units.md`, `studio_core/__init__.py`,
  `tasks/SYS-CI-0012.json` (검증기 입력 해시 갱신)
- 되돌리는 방법: 추가된 파일을 제거하고 변경된 파일을 이전 커밋 상태로 복원한다.
  파괴적 Git 명령은 사용하지 않는다. 복원 후 `python scripts/validate_baseline.py`와
  `python -m unittest discover -s tests -v`를 다시 실행해 기준선이 이전 상태로 돌아왔음을
  확인한다.
- 런타임 롤백은 필요 없다. 이 유닛은 운영 환경에 배포되지 않았고 저장소 안에 데이터베이스
  파일을 남기지 않는다.

## 8. 다음 담당자에게 보내는 단일 요청

`A-50`은 `handoffs/R2-DBC-0002-handoff.json`을 접수하고, 독립 콘솔에서
`python scripts/validate_baseline.py`와 `python -m unittest discover -s tests -v`를
재실행한 뒤 `code-reviewer` 독립 검토를 지시하고, 그 결과를 근거로 `R2-DBC-0002`의 최종
QA 게이트 판정을 발행하라.

## 9. 인간 게이트

아래 항목은 **전부 미발행**이다. 구현자는 이 중 어느 것도 스스로 체크할 수 없다.

- [ ] `A-50` QA Lead 검토 및 최종 QA 게이트 판정
- [ ] `A-02` Platform Integrator 검토
- [ ] `A-00` Studio Director 검토
- [ ] `USER` 최종 승인
- [ ] `code-reviewer` 독립 읽기 전용 코드 검토 완료
- [ ] Artifact 상태 `SUBMITTED` → `REVIEWED` 이상으로 승격 및 `approved_at` 기록
- [ ] 커밋·푸시 승인 (현재 미수행)

`artifacts/R2-DBC-0002-artifact.json`의 `specification.human_approved`는 `false`이고
`approved_at`은 비어 있다. 두 값이 이 절의 상태와 어긋나면 검증기가 실패한다.
