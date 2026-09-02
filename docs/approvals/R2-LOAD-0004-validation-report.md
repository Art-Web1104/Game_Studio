# R2-LOAD-0004 검증 보고서

- 작업: `tasks/R2-LOAD-0004.json` (`READY`, 소유자 `A-02`, 위험 `MEDIUM`)
- 계약: `games/roulette/load-observation-contract.yaml`
- 설계 문서: `docs/games/R2-load-observation.md`
- 하네스: `scripts/observe_r2_load.py`
- 시험: `tests/test_load_observation.py`
- 감사 기록: `audit/events/R2-LOAD-0004-events.json`
- 작성자: `A-02` (구현자). **이 문서는 구현자의 자체 점검 기록이며 승인이 아니다.**

## 1. 무엇을 주장하고 무엇을 주장하지 않는가

주장한다: 아래 2절에 적은 실행이 실제로 일어났고, 그 결과가 적힌 그대로였다.

주장하지 않는다: 전체 시험 스위트의 PASS, 기준선 검증기의 PASS, 독립 최종 판정, `A-50`/`USER`
게이트 판정, 호스티드 CI 관측, 운영 준비 완료, `R5` 일정. 3절과 8절이 각각의 실제 상태다.

수치는 주장의 대상이 아니다. 이 문서는 지연·처리량·`serialization_wait_proxy_ms`의 구체적
관측값을 싣지 않는다. 그 값들은 실행 환경에 종속되며, 증거 문서에 박히는 순간 목표치로
재해석될 여지가 생긴다. 계약 `observed_metrics.asserted_by_tests`는 `false`이고 시험은 그
값들의 크기를 보지 않는다.

## 2. 실행한 것과 그 결과

### 2.1 1차 구현 (누수 수정 이전)

| 실행 | 결과 |
| --- | --- |
| `python -m unittest tests.test_load_observation` (집중, 3회 반복) | 98건, 3회 모두 PASS |

집중 시험이 통과한 **이후에** Windows SQLite 핸들 누수가 발견되었다. 시험이 초록색이었다는
사실은 자원이 회수되었다는 뜻이 아니었다. 이 순서는 감사 기록에 그대로 남는다.

### 2.2 재작업 이후 (구현자 자체 점검)

| 실행 | 결과 |
| --- | --- |
| `python -m py_compile` (하네스·시험) | PASS |
| 작은 관측 1회 (동시성 2, 라운드 2, 워밍업 1) | 정확성 속성 10/10 `true` |
| 같은 실행의 서버 작업자 스레드 | 11개 시작, 11개 조인 |
| 같은 실행의 임시 작업 공간 | 새로 남은 것 없음 |
| `python -m unittest tests.test_load_observation` (집중) | 98건 PASS |

### 2.3 재작업 이후 (Codex 독립 실행)

| 실행 | 결과 |
| --- | --- |
| `python -m unittest tests.test_load_observation -v` | 98건 PASS, 2.673초 |
| `python -m compileall` | PASS |
| `python scripts/scan_secrets.py` | PASS (204개 파일, 평문 비밀값 0건) |

2.673초는 그 실행 환경의 관측 기록이며 성능 약속이 아니다.

## 3. 전체 시험 스위트 — PASS로 부르지 않는다

최종 핸드오프 이전에 `python -m unittest discover -s tests -v`를 실행했다. 결과는 다음과 같다.

- 총 706건, 4건 건너뜀
- 실패 1건. `operations/collaboration.yaml`의 `completion_gate`에 대한 자기 게이트 오류이며,
  이 유닛의 핸드오프가 `readiness: REWORK_REQUIRED`이고 두 표준 명령을 `NOT_RUN`으로 유지하기
  때문에 발생한다. 예상된 실패이고 유일한 실패다.
- **기준선(변경 이전)에서도 같은 자기 게이트 실패가 난다.** 이 유닛이 만든 실패가 아니다.

이 실행을 **PASS로 부르지 않는다.** `python scripts/validate_baseline.py`도 같은 자기 게이트
단계에서 막히므로 마찬가지로 PASS로 부르지 않는다. 실행하지 않은 것을 통과로 적지 않는 것과
같은 이유로, 실패한 것을 통과로 적지도 않는다.

이 충돌은 구현 결함이 아니라 계약 단계 산출물과 완료 게이트 규칙의 선언 충돌이다. 규칙 개정으로
풀지 다른 방식으로 풀지는 승인 주체가 판정할 사항이며, 구현자가 `readiness`를 임의로 올려
해소해서는 안 된다. 이 위험은 `handoffs/R2-LOAD-0004-handoff.json`에 `HIGH`로 이미 기록되어
있다.

이 단계에서는 전체 스위트도 기준선 검증기도 다시 실행하지 않았다. 이 단계의 검증은 JSON·스키마
유효성과 마크다운 산출물 존재 확인으로 한정했다.

## 4. Windows SQLite 핸들 누수 — 원인과 재작업

전체 서술은 `docs/games/R2-load-observation.md` 6절에 있다. 요약은 다음과 같다.

**증상.** 관측 종료 후에도 `ts-studio-r2-load-*` 임시 작업 공간이 삭제되지 않았다.

**원인(네 가지가 겹쳤다).**

1. `sqlite3` 연결은 그것을 연 스레드에 묶이고, `DurableRoundStore`는 스레드 지역 연결을 쓴다.
2. `ThreadingHTTPServer`는 수락된 연결마다 자기 스레드에서 서비스하므로, 요청을 처리한 작업자
   스레드마다 관측 데이터베이스 연결이 하나씩 열린다.
3. 주 스레드의 `store.close()`는 그 연결들을 닫을 수 없다. 다른 스레드의 연결을 닫으면
   `sqlite3.ProgrammingError`(=`sqlite3.Error`의 하위 클래스)가 나고, 저장소의 종료 경로는 그
   예외를 무해한 이중 닫기로 보고 삼킨다. 핸들은 열린 채로 남는다.
4. 슬라이스가 `daemon_threads = True`이므로 `socketserver`는 작업자 목록을 보관하지 않고
   `server_close`는 아무도 조인하지 않는다.

Windows에서는 열린 핸들 하나가 파일 잠금 하나이므로 삭제가 실패했다.

**반영한 재작업.**

- 요청별 `ThreadingHTTPServer` 작업자가 **자기 핸들러 스레드 안에서** 저장소의 공개 메서드
  `DurableRoundStore.release_thread_connection()`을 `handle()`의 `finally`에서 호출한다. 연결을
  연 스레드만이 그것을 닫을 수 있기 때문이다. 이 메서드는 `studio_core/durable_state.py`에 이미
  존재하던 공개 API이며, 그 동결 파일은 수정되지 않았다.
- 서버가 보관하지 않는 작업자 목록을 하네스가 `setup()` 등재로 보관한다.
- 서빙 스레드와 작업자 스레드의 **모든 조인이 유계**다. 마감 시한을 넘기면
  `SERVER_THREAD_DEADLINE_EXCEEDED`/`SERVER_WORKER_DEADLINE_EXCEEDED`로 거절한다. 무한 조인도
  고정 대기도 없다.
- `ignore_cleanup_errors`는 **제거**했다. 삭제 실패는 핸들이 실행보다 오래 살았다는 유일한
  신호이고, 그것을 끄는 것은 고치는 것이 아니다. 대신 정리 이후 부재를 긍정문으로 확인하고
  남아 있으면 `WORKSPACE_NOT_RELEASED`로 거절한다.
- 요청마다 새 연결과 `Connection: close`를 써서 유지 소켓이 작업자 스레드를 붙잡지 않게 한다.

**정리 확인.** 재작업 이후의 작은 실행에서 작업자 11개가 시작·조인되었고 새 임시 작업 공간이
남지 않았다. 거절 경로 쪽은 `BoundedRefusalTestCase`가 실행 전후 작업 공간 집합의 차이가
공집합임을 확인한다.

## 5. 수용 기준별 증거

| 기준 | 증거 | 상태 |
| --- | --- | --- |
| AC-001 표준 라이브러리 전용, 새 경로·모듈 없음 | `SourceDisciplineTestCase` (import 정적 검사, 의존성 매니페스트 부재), `ObservedSliceTestCase` (`ROUTES` 4개, 모듈 목록) | 집중 시험 PASS |
| AC-002 유계 실행과 거절 | `BoundedRefusalTestCase` (트립와이어 + 상한·비루프백 네거티브), 계약↔상수 대조 | 집중 시험 PASS |
| AC-003 정산 정확성 | `ObservationRecordTestCase.test_settlement_reconciles_to_the_minimum_unit_in_integers` 외 | 집중 시험 PASS |
| AC-004 동시 멱등성 | 배리어 동기화 동시 스핀 + 엔트로피 계측, `duplicate_request_id_commits_once` | 집중 시험 PASS |
| AC-005 감사 완전성 | `test_audit_events_are_unique_and_match_the_committed_rounds`, 재적재 후 체인 검증 | 집중 시험 PASS |
| AC-006 통계 산출 정의 | `StatisticsTestCase` (고정 표본 결정론, 보간 없음), 계약↔코드 정의 대조 | 집중 시험 PASS |
| AC-007 측정은 관측이며 판정 기준 아님 | `test_no_test_in_this_suite_makes_an_ordering_comparison` (AST 순서 비교 0건), `test_the_harness_never_compares_an_observed_metric` | 집중 시험 PASS |
| AC-008 직렬화 프록시 분리와 한계 명시 | 별도 출력 키, 계약 6절과 설계 문서 5절, 런타임 계측 부재 확인 | 집중 시험 PASS |
| AC-009 동결 경로 무변경 | `FrozenInputTestCase` (inputs 29건 정규 LF 해시 대조) | 집중 시험 PASS |
| AC-010 범위 밖 미수행 | 계약 `out_of_scope`, `test_the_contract_leaves_the_out_of_scope_items_open` | 집중 시험 PASS |
| AC-011 R4·자산·아트 무접촉 | `ScopeBoundaryTestCase` 5건 | 집중 시험 PASS |
| AC-012 신규 파일만 생성 | `test_this_unit_declares_only_new_files_as_deliverables`, 변경 파일 목록 | 집중 시험 PASS |
| AC-013 결정론 | `RepeatedObservationTestCase` (2회 실행 구조·판정 동일), `sleep` 부재 검사 | 집중 시험 PASS |
| AC-014 두 표준 명령 + 비밀값 스캔 | 비밀값 스캔은 Codex 실행 PASS(204개 파일). **두 표준 명령은 3절에 따라 PASS가 아니다.** | **미충족** |

AC-014는 충족되지 않았다. 3절의 자기 게이트 충돌이 해소되기 전에는 두 표준 명령이 PASS가 될 수
없고, 이 충돌의 해소 방식은 승인 주체가 판정할 사항이다.

## 6. 변경한 경로

**신규 6건**: `games/roulette/load-observation-contract.yaml`, `scripts/observe_r2_load.py`,
`tests/test_load_observation.py`, `docs/games/R2-load-observation.md`,
`docs/approvals/R2-LOAD-0004-validation-report.md`, `audit/events/R2-LOAD-0004-events.json`

**계약 3종(이전 단계에서 생성)**: `tasks/R2-LOAD-0004.json`,
`artifacts/R2-LOAD-0004-artifact.json`, `handoffs/R2-LOAD-0004-handoff.json`

**수정 0건.** 이 유닛은 저장소에 이미 존재하던 파일을 하나도 수정하지 않았다.
`scripts/validate_baseline.py`도, 계약이 고정한 동결 경로 17개도 무변경이다. 해시 재고정도 0건이며
`tasks/R4-ART-0007.json`과 그 자산·이미지 산출물에는 어떤 방식으로도 접근하지 않았다.

## 7. 남은 결함과 위험

- **저장소 밖 임시 작업 공간 20개.** 수정 이전의 버그가 만든 것으로, 이 작업에서 삭제하지
  않았다. 저장소 안이 아니며 설계상 로컬 SQLite 관측 잔여물만 들어 있고 비밀값은 없다. 그래도
  명시적 정리가 필요한 미해결 항목이다.
- **완료 게이트 자기 충돌.** 3절. 기준선에서도 동일하게 재현되며 승인 주체의 판정이 필요하다.
- **관측치의 재해석 위험.** 지연·처리량과 프록시 값이 나중에 용량 목표치나 통과 기준으로 인용
  되면 이 유닛이 명시적으로 거부한 SLO가 사실상 성립하게 된다. 인용하는 문서는 그것이 특정
  실행의 기록임을 함께 표기해야 한다.
- **프록시의 해석 한계.** `serialization_wait_proxy_ms`는 내부 잠금 대기의 측정값이 아니며
  직렬화 비용의 정량 근거로 쓸 수 없다.
- **단일 사용자 범위.** 여러 사용자의 실제 동시 접속 경합은 관측되지 않았다. 다중 사용자
  신원·세션 분리 결정 이후 별도 유닛이 필요하다.
- **`R2-SEC-0005`는 범위 밖의 미승인 후보로 열린 채 남는다.** 이 유닛의 부하 관측이 공격 표면
  검증을 대신하지 않는다.
- **로컬 통과가 Linux 러너 통과를 보장하지 않는다.** 특히 이 유닛의 자원 회수 문제는 Windows
  파일 잠금 의미론에서 드러났으므로, 다른 플랫폼에서의 관측은 별도 증거가 필요하다.

## 8. 인간 게이트

| 게이트 | 상태 |
| --- | --- |
| Codex 독립 실행 (집중 시험·컴파일·비밀값 스캔) | 2.3절 기준 완료 |
| 독립 최종 판정 | `NOT_RUN` |
| `A-20` 코드 검토 | `NOT_RUN` |
| `A-50` QA 판정 | `NOT_RUN` |
| `USER` 최종 승인 | `NOT_RUN` |
| 호스티드 CI 관측 | `NOT_RUN` |
| 운영 준비 완료 | `PENDING` |
| 커밋·푸시·병합 | 수행하지 않음 |

`R5` 승인 이전이므로 상용 제작 일정과 출시일을 확정하지 않는다. 용량 목표치, 임계값, 용량
약속도 이 문서 어디에도 선언되지 않는다.
