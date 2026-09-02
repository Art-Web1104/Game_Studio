# R2-QA-0006 종결 후보 증거 보고서

- 작업: `tasks/R2-QA-0006.json` (`READY`, 소유자 `A-20`, 위험 `HIGH`)
- 대상 유닛: `R2-RNG-0001`, `R2-DBC-0002`, `R2-NET-0003`, `R2-LOAD-0004`, `R2-SEC-0005`
- 상태 문서: `docs/status/R2-QA-0006-closure-candidate.md`
- 감사 기록: `audit/events/R2-QA-0006-events.json`
- 교차 검증 시험: `tests/test_r2_qa_closure.py`
- 작성자: `A-20` (구현자). **이 문서는 구현자의 자체 점검 기록과, 독립 검증자가 공급한 판정의
  전사이며, 승인도 최종 QA 게이트 판정도 아니다.**

## 0. 종결 상태와 미발행 게이트

| 항목 | 값 |
| --- | --- |
| 종결 상태 | `CLOSED_PENDING_DIRECTOR_AND_USER` |
| 독립 검증 판정 (`codex` 콘솔, `independent_verifier` 역할, `A-50` 대행) | `PASS` |
| 종결 후보 권고 (독립 검증자 발행) | `ISSUED` |
| `A-50` 최종 QA 게이트 판정 | `NOT_RUN` |
| `A-02` 게이트 판정 | `NOT_RUN` |
| `A-00` 게이트 판정 | `NOT_RUN` |
| `USER` 최종 QA 승인 | `NOT_RUN` |
| 이 유닛에 대한 호스티드 CI 관측 | `NOT_RUN` |
| 커밋·푸시·병합 | `NOT_RUN` |

독립 검증 판정: `PASS`. 종결 후보 권고: `ISSUED`. 이 두 값은 2026-09-03에 `codex` 콘솔이
`operations/collaboration.yaml`의 `independent_verifier` 역할로 `A-50`을 대행해 발행한 판정이며,
원문은 5절에 그대로 옮겼다. `A-20`(Claude)은 이 판정을 발행하지 않았고 스스로 독립 검증을
수행하지도 않았다. 이 문서에서 `A-20`이 한 일은 공급된 판정을 옮겨 적은 것뿐이다.

독립 검증은 `operations/collaboration.yaml`의 `INDEPENDENT_VERIFY` 단계이고 `FINAL_GATE`가
아니다. `A-50` 최종 QA 게이트 판정: `NOT_RUN`. `A-02` 게이트 판정: `NOT_RUN`.

`A-00` 게이트 판정: `NOT_RUN`. `USER` 최종 QA 승인: `NOT_RUN`. 사용자의 지시는 착수와
저장소·PR 작업 흐름의 자율 수행을 허가한 것이고 최종 QA 승인이 아니다.

종결 후보는 종결이 아니다. 이 문서는 승인 주체가 판정할 재료를 한자리에 모으고 교차 검증한
결과이며, 그 자체로 최종 게이트 판정이 아니다.

## 1. 무엇을 주장하고 무엇을 주장하지 않는가

주장한다.

- 3절에 적은 저장소 안 재현 검증이 실제로 수행되었고 결과가 적힌 그대로였다.
- 4절에 적은 외부 증거는 `A-50`이 공급한 값을 문자 그대로 옮긴 것이다.
- 5절에 적은 독립 검증 판정은 `codex` 콘솔이 발행해 공급한 값을 문자 그대로 옮긴 것이다.
- 이 유닛은 신규 파일 7건만 만들었고 기존 파일을 하나도 수정하지 않았다.

주장하지 않는다.

- 다섯 유닛의 QA 합격, 승인, 종결. 어느 것도 이 문서가 판정하지 않는다.
- 운영 준비 완료, 배포 가능성, 용량·SLO 특성, `R5` 이후의 일정.
- `A-50` 최종 QA 게이트, `A-02`, `A-00`, `USER`의 게이트 판정. 전건 미발행이다.
- `A-20`이 독립 검증을 수행했다는 사실. 5절의 판정은 `A-20`의 것이 아니다.

## 2. 증거의 갈래와 그 출처

이 패킷의 증거는 성격이 다른 네 갈래이며 섞어 읽으면 안 된다. 수행자와 관측 시점이 서로 다르고,
어느 한 갈래가 다른 갈래를 대신하지 않는다.

| 갈래 | 내용 | 출처 | 수행자 |
| --- | --- | --- | --- |
| 저장소 안 재현 | 삼중 계약 정합성, 동결 해시, 감사 연쇄, 문서 일관성 | 작업 트리 | `A-20` (이 유닛) |
| `A-50` 공급 사전 증거 | f564bce 시점 명령 실행 결과 | `A-50`의 독립 실행 | `A-50` |
| `A-50` 공급 외부 증거 | 다섯 PR의 병합과 호스티드 CI 체크 | `GitHub CLI evidence supplied by A-50` | `A-50` |
| 독립 검증 판정 | 이 유닛 신규 7건에 대한 독립 재실행과 판정 | `codex` 콘솔 (`independent_verifier`, `A-50` 대행) | `A-50` |

`A-50` 공급 증거와 독립 검증 판정은 Claude가 만든 것이 아니다. Claude는 이 값을 재조회하지
않았고 독립 검증을 대신 수행하지도 않았다. 이 작업에서 저장소 밖 네트워크에 접근하지 않았다.
계약의 `security.network_policy`는 `NONE`이다.

공급된 값이 틀렸다면 이 문서의 기록도 틀린다. 이 문서는 값을 그대로 옮겼다는 것 이상을
주장하지 않으며, 진위 확인 책임은 값을 공급한 콘솔과 최종 게이트 승인자에게 있다.

## 3. `A-20` 자체 점검 — 이 구현 상태에 대한 실행

아래는 5절의 독립 검증 판정을 전사한 뒤의 작업 트리에서 `A-20`이 직접 실행한 결과다. 4절의
`A-50` 공급 증거와도, 5절의 독립 검증 관측과도 출처와 시점이 다르다. 전사가 산출물을 바꾸므로
종결 스위트와 전체 시험의 건수는 5절보다 크다.

| 명령 | 관측 결과 |
| --- | --- |
| `python -m unittest tests.test_r2_qa_closure -v` | Ran 101 tests, OK, 종료 코드 0 |
| `python -m unittest tests.test_rng tests.test_durable_state tests.test_reconnect_continuity tests.test_load_observation tests.test_security_verification -v` | Ran 405 tests, OK, 종료 코드 0 |
| `python scripts/validate_baseline.py` | 20단계 PASS, 0단계 FAIL, 종료 코드 0 |
| `python -m unittest discover -s tests -v` | Ran 893 tests, OK, skipped=4, 실패 0건, 오류 0건, 종료 코드 0 |
| `python -m compileall -q studio_core scripts tests` | 종료 코드 0 |
| `python scripts/scan_secrets.py` | 223개 파일, 평문 자격증명 0건, 종료 코드 0 |

이 값들은 `A-20 자체 점검`의 관측이며 독립 검증이 아니다. 같은 명령을 Codex가 독립 콘솔에서
재실행해야 독립 증거가 된다. 그 재실행은 이후 `codex` 콘솔에서 수행되었고, 그 관측값과 판정은
5절에 공급된 그대로 옮겨 적었다. 3절과 5절은 수행자가 다르며 3절이 5절을 대신하지 않는다.

`python -m unittest discover -s tests -v`와 `python scripts/validate_baseline.py`는 이 유닛의
Handoff Packet이 `readiness: READY_FOR_QA`로 갱신되고 두 표준 명령을 `PASS`로 기록한 정확한
상태에 대해 실행되었다. `validate_collaboration` 단계는 모든 계약의 Handoff에 허용된 readiness와
두 명령의 `PASS` 기록을 요구하므로, 그 이전 상태에서는 두 명령이 실패했고 이 보고서는 그 사실을
감추지 않는다. `READY_FOR_QA`는 독립 검증이 끝나 최종 QA 게이트를 기다린다는 뜻이며 QA를
통과했다는 뜻이 아니다.

만약 최종 상태에서 두 명령 중 하나라도 실패했다면 이 유닛의 `readiness`는
`REWORK_REQUIRED`로 되돌아가고 결과는 `FAIL`로 기록되어야 한다. 그 규칙은 문장이 아니라
`tests/test_r2_qa_closure.py`의 `evaluate_closure_readiness`라는 실행 가능한 경로로 존재한다.

## 4. `A-50` 공급 증거 — 원문 그대로

### 4.1 f564bce 시점의 명령 실행 (`A-50` 독립 실행)

| 명령 | `A-50` 관측 결과 |
| --- | --- |
| `python -m unittest tests.test_rng tests.test_durable_state tests.test_reconnect_continuity tests.test_load_observation tests.test_security_verification -v` | 종료 코드 0, Ran 405 tests, OK |
| `python scripts/validate_baseline.py` | 종료 코드 0, 20단계 PASS, 0단계 FAIL |
| `python -m unittest discover -s tests -v` | 종료 코드 0, Ran 792 tests, OK, 4건 건너뜀 |
| `python scripts/scan_secrets.py` | 종료 코드 0, 216개 파일, 발견 0건 |

이 실행은 f564bce 시점의 깨끗한 작업 트리를 대상으로 했다. 기준 커밋은
`f564bce93c4099ba31f395f139c1561eb548a82b`다. 이 계약 3종과 구현 4종이 추가된 현재 상태에 대한
관측이 아니다. 두 상태를 같은 것으로 읽으면 잘못된 결론에 이른다. 현재 상태에 대한 관측은
3절에 따로 적혀 있다.

### 4.2 다섯 PR의 호스티드 CI (`GitHub CLI evidence supplied by A-50`)

저장소: `https://github.com/Art-Web1104/Game_Studio`. 각 PR마다 세 체크가 발행되었고 세 건 모두
결론은 `SUCCESS`였다. 체크 이름은 `.github/workflows/ci.yml`의 잡 이름과 같다.

- `Baseline, tests and compile (Python 3.11)`
- `Baseline, tests and compile (Python 3.12)`
- `Repository secret scan`

| 유닛 | PR | URL | 병합 시각 | 병합 커밋 | 세 체크 |
| --- | --- | --- | --- | --- | --- |
| `R2-RNG-0001` | PR #2 | `https://github.com/Art-Web1104/Game_Studio/pull/2` | `2026-09-01T11:41:04Z` | `69b314595293444b07d5b490d2f6707a4245d9a9` | `SUCCESS` |
| `R2-DBC-0002` | PR #4 | `https://github.com/Art-Web1104/Game_Studio/pull/4` | `2026-09-01T12:27:58Z` | `8a3f9867e67a4bb6a4e07b23af7297f4f2f735e9` | `SUCCESS` |
| `R2-NET-0003` | PR #11 | `https://github.com/Art-Web1104/Game_Studio/pull/11` | `2026-09-02T08:58:52Z` | `13d826427ad3c55c36f861fa1fc56961dd474559` | `SUCCESS` |
| `R2-LOAD-0004` | PR #12 | `https://github.com/Art-Web1104/Game_Studio/pull/12` | `2026-09-02T11:11:52Z` | `70bcd9d9bf96b4d0fcbe38492d0ea6ab0e95968d` | `SUCCESS` |
| `R2-SEC-0005` | PR #13 | `https://github.com/Art-Web1104/Game_Studio/pull/13` | `2026-09-02T13:12:55Z` | `f564bce93c4099ba31f395f139c1561eb548a82b` | `SUCCESS` |

이 표의 값은 `A-50`이 GitHub CLI로 취득해 공급한 것이다. Claude는 이 값을 재조회하지 않았다.
이 유닛 자체에 대한 호스티드 CI는 커밋과 푸시를 하지 않았으므로 `NOT_RUN`이다.

## 5. 독립 검증 판정 — 공급된 원문

이 절의 값은 `codex` 콘솔이 `operations/collaboration.yaml`의 `independent_verifier` 역할로
`A-50`을 대행해 2026-09-03에 발행한 판정이다. `A-20`은 이 판정을 발행하지 않았고 스스로 독립
검증을 수행하지도 않았으며, 공급된 값을 옮겨 적는 일만 했다. 프로토콜의
`separation_of_duties`는 생성자의 자기 검증과 자기 승인을 금지하고, 이 기록은 그 경계를 지킨다.

### 5.1 검토 범위

이 유닛이 추가한 미추적 신규 파일 7건. 기존 추적 파일의 수정은 0건으로 확인되었다.

그 관측은 이 판정을 전사하기 **이전** 개정(아티팩트 `2.0.0`, 핸드오프 `HO-R2-QA-0006-002`,
종결 스위트 84건)에 대한 것이다. 판정을 기록하는 행위 자체가 같은 일곱 파일을 바꾸므로, 이
전사 개정(아티팩트 `2.1.0`, 핸드오프 `HO-R2-QA-0006-003`)은 아직 독립 검증되지 않았다. 3절과
5절의 건수가 다른 이유가 그것이며, 이 문서는 그 차이를 감추지 않는다.

### 5.2 독립 재실행 결과

| 명령 | 독립 검증자 관측 결과 |
| --- | --- |
| `python -m unittest tests.test_r2_qa_closure -v` | 84 tests OK |
| `python -m unittest tests.test_rng tests.test_durable_state tests.test_reconnect_continuity tests.test_load_observation tests.test_security_verification -v` | 405 tests OK |
| `python scripts/validate_baseline.py` | 20 PASS, 0 FAIL |
| `python -m unittest discover -s tests -v` | 876 tests OK, skipped=4 |
| `python -m compileall` | PASS |
| `python scripts/scan_secrets.py` | 223개 파일, 0건 |

### 5.3 84건 종결 스위트가 확인한 범위

54개 동결 입력 해시 전부, 원천 삼중 계약, 결속된 구성 요소 해시 25건, 종결 아티팩트의 구성
요소 해시, 감사 기록의 요청·이벤트 해시 연쇄, 호스티드 CI 증거의 전사, 직무 분리, 종결 경계.

### 5.4 판정

| 항목 | 값 |
| --- | --- |
| 독립 검증 판정 | `PASS` |
| 종결 후보 권고 | `ISSUED` |
| 발행 콘솔·역할 | `codex` / `independent_verifier` (`A-50` 대행) |
| 발행 일자 | 2026-09-03 |
| 기록자 | `A-20` (전사만 수행) |

### 5.5 이 판정이 아닌 것

이것은 `FINAL_GATE`가 아니고 `USER` 승인도 아니다. `A-00`, 해당되는 경우의 `A-02`, `USER`,
이 신규 유닛에 대한 호스티드 CI, 커밋·푸시·병합은 전부 `NOT_RUN`으로 남는다. 전체 상태는
`CLOSED_PENDING_DIRECTOR_AND_USER`에 머문다.

### 5.6 판정과 함께 유지되는 한계

로컬·단일 사용자 참조 범위에 한정되며 운영·외부 환경, SLO, 용량, 일정에 대한 판정이 아니다.
`R2-LOAD-0004`의 수정 이전 결함이 남긴 임시 작업 공간 20건은 정리 부채로 남아 있다.
`R4-ART-0007`은 별개이며 `A-30`의 권리 판정에 막혀 있다.

## 6. 저장소 안 교차 검증 결과

`tests/test_r2_qa_closure.py`가 확인한 것을 항목별로 적는다. 각 항목은 그 시험이 실패하면
이 보고서의 해당 줄도 성립하지 않는다는 뜻이다.

| 항목 | 확인 내용 | 결과 |
| --- | --- | --- |
| 삼중 계약 15개 | 스키마 유효, `task_id`·`project_id`·`artifact_id` 정렬, 파일명 일치 | `PASS` |
| 생성자·검토자 분리 | 다섯 아티팩트 모두 생성자가 자기 검토자 목록에 없음 | `PASS` |
| 발신자·수신자 분리 | 다섯 Handoff 모두 `from_agent_id != to_agent_id` | `PASS` |
| 필수 명령 증거 | 다섯 Handoff 모두 두 표준 명령을 `PASS`로 기록 | `PASS` |
| 아티팩트 1차 결속 | 다섯 아티팩트의 `uri` 정규 LF 해시가 `content_hash`와 일치 | `PASS` |
| 구성 요소 해시 | 유닛별 실제 키 이름 25건 전부가 실제 파일과 일치 | `PASS` |
| 해시 키 누락 | 선언된 `sha256:` 키 중 검사되지 않은 것 0건 | `PASS` |
| 동결 입력 54건 | 선언 해시와 실제 정규 LF 해시가 전부 일치 | `PASS` |
| 감사 기록 6건 | 스키마 유효, 연쇄 검증 문제 0건 | `PASS` |
| 신규 산출물 | 아티팩트·핸드오프 스키마 유효, 구성 요소 해시 4건 일치 | `PASS` |
| 실패 강제 경로 | 합성 실패 주입 시 종결 권고 차단, `REWORK_REQUIRED` 산출 | `PASS` |
| 위생 | 신규 7건에 자격증명·절대 경로·호스트명·계정명 0건 | `PASS` |
| 독립 검증 판정 전사 | 공급된 `PASS`와 `ISSUED`가 아티팩트·핸드오프·감사 기록·상태 문서에 같은 값으로 기록됨 | `PASS` |
| 판정 주체 분리 | 산출물 어디에도 `A-20`이 독립 검증을 수행했거나 최종 게이트를 판정했다는 기술이 없음 | `PASS` |

### 6.1 유닛마다 다른 해시 키 이름

다섯 유닛은 서로 다른 이름 규칙으로 구성 요소 해시를 선언했다. 하나의 접두사 규칙을 가정하고
검사하면 규칙 밖의 키가 조용히 검사되지 않는다. 그래서 시험은 유닛별 실제 키 이름을 그대로
묶고, 선언된 `sha256:` 값 키 집합이 그 묶음으로 빠짐없이 덮이는지를 함께 단언한다.

| 유닛 | 실제 키 이름 | 결속 |
| --- | --- | --- |
| `R2-RNG-0001` | `statistics_module_hash`, `record_schema_hash` | 파일 대조 |
| `R2-RNG-0001` | `recovered_draft_hash` | 폐기 초안이므로 파일 결속 없음, 사유 기록 |
| `R2-DBC-0002` | `contract_hash`, `sql_schema_hash`, `test_hash`, `test_suite_hash` | 파일 대조 |
| `R2-NET-0003` | `contract_hash`, `test_suite_hash`, `validator_hash`, `design_document_hash`, `task_contract_hash` | 파일 대조 |
| `R2-LOAD-0004` | `task_contract_hash`와 `component_hash_*` 6건 | 파일 대조 |
| `R2-SEC-0005` | `task_contract_hash`와 `component_hash_*` 6건 | 파일 대조 |

### 6.2 기존 단언은 완화되지 않았다

교차 검증은 기존 시험을 재실행하거나 문서 간 값을 대조하는 방식으로만 수행했다. 통과시키기
위해 단언을 완화하거나 건너뛴 경로는 채택하지 않았다. 다섯 시험 모듈의 정규 LF 해시가 계약의
동결 선언값과 같다는 사실이 그 증거이며, 시험이 그 동일성을 직접 단언한다.

## 7. 가산성과 변경 범위

| 항목 | 값 |
| --- | --- |
| 이 유닛이 만든 신규 파일 | 7건 |
| 이 유닛이 수정한 기존 파일 | 0건 |
| 기존 계약의 무결성 재고정 | 0건 |
| `scripts/validate_baseline.py` 변경 | 없음 |
| `scripts/validate_baseline.py`에 단계 추가 | 없음 |

신규 7건은 다음과 같다.

- 계약 단계 3건: `tasks/R2-QA-0006.json`, `artifacts/R2-QA-0006-artifact.json`,
  `handoffs/R2-QA-0006-handoff.json`
- 구현 단계 4건: `docs/approvals/R2-QA-0006-closure-report.md`,
  `docs/status/R2-QA-0006-closure-candidate.md`, `audit/events/R2-QA-0006-events.json`,
  `tests/test_r2_qa_closure.py`

기존 Task, Artifact, Handoff, 승인 보고서, 상태 문서, 런타임, 시험, 스크립트, 정책, 계약을
하나도 다시 쓰지 않았다. 신규 파일만 만들어 무결성 해시 연쇄를 일으키지 않았다.

## 8. R4 경계

`R4-ART-0007`의 아트 권리와 통합은 이 유닛과 별개이고 차단 상태다. 상태 값은
`SEPARATE_AND_BLOCKED`이며 차단 사유는 `A-30`의 권리 판정 미완이다. 이 유닛이 그 상태를
바꾸지도 종결을 주장하지도 않는다. 이 계약의 입력 54개와
산출물 6개 어디에도 R4 경로, 자산, 이미지, 아트 경로가 없다. 무결성 재고정 연쇄가 그 경로에
닿지 않는다. 이 유닛은 아트 산출물을 만들지도 검토하지도 않았다.

## 9. 알려진 한계

여섯 항목은 축약하거나 삭제하지 않는다.

### 한계 1: 단일 사용자 로컬 참조 구현 범위

다섯 유닛의 증거는 단일 사용자 로컬 참조 구현에 대한 것이다. 다중 사용자, 다중 노드, 실제
플레이어 트래픽은 이 범위 밖이다.

### 한계 2: 운영·외부 환경 비대상

운영 환경과 외부 환경은 대상이 아니다. 이 유닛은 저장소 밖 네트워크에 접근하지 않았고 운영
데이터·배포 환경을 건드리지 않았다. 호스티드 CI 결과는 공급된 외부 증거일 뿐 운영 관측이 아니다.

### 한계 3: SLO·용량 약속 없음

이 문서는 지연 시간, 처리량, 가용성, 동시 접속 수 어느 것에 대해서도 목표치를 정하지 않는다.
`R2-LOAD-0004`는 관측 유닛이고 그 관측값은 실행 환경에 종속되며 약속이 아니다.

### 한계 4: `R5` 승인 이전 일정 확정 금지

`R5` 승인 이전이므로 상용 제작 일정, 기간, 마감, 출시일, 배포 계획을 확정하지 않는다.
`agents/registry.yaml`의 `production_schedule_policy: prohibited_before_r5`가 유효하다.

### 한계 5: `R2-LOAD-0004` 수정 이전 결함이 남긴 임시 작업 공간 20건

`R2-LOAD-0004`의 수정 이전 결함이 저장소 밖 운영체제 임시 디렉터리에 임시 작업 공간 20건을
남겼다. 접두사는 `ts-studio-r2-load-`다. 이 유닛은 그것을 제거하지 않으며, 독립적으로 제거되었음이
확인되기 전까지 로컬 정리 부채로 남는다. 절대 경로는 어떤 산출물에도 기록하지 않는다. 정리를
어느 유닛이 수행하고 그 제거를 어떤 증거로 확인할지는 승인 주체의 판정이 필요하다.

### 한계 6: `R2-SEC-0005` 현재 실행의 임시 작업 공간 잔여 0건

`R2-SEC-0005`의 현재 실행은 임시 작업 공간 잔여가 0건이다. 이 사실은 한계 5의 20건을 상쇄하지
않는다. 두 값은 서로 다른 유닛의 서로 다른 실행에 대한 것이다.

## 10. 남은 위험

| 심각도 | 위험 |
| --- | --- |
| `HIGH` | 종결 후보가 종결로 인용될 위험. 다섯 유닛의 증거가 한자리에 모였다는 사실이 승인되었다는 뜻으로 읽혀서는 안 된다. |
| `HIGH` | 공급된 외부 증거의 진위는 이 유닛이 확인할 수 없다. 값이 틀리면 이 문서의 기록도 틀린다. 5절의 독립 검증 판정도 공급된 값이며 `A-20`이 재현한 것이 아니다. |
| `HIGH` | 독립 검증 `PASS`가 최종 게이트로 인용될 위험. 5절의 판정은 `INDEPENDENT_VERIFY` 단계이고, `A-50` 최종 QA 게이트·`A-02`·`A-00`·`USER` 승인과 이 유닛에 대한 호스티드 CI는 전부 미발행이다. |
| `MEDIUM` | 계약이 54개 경로를 고정하므로, 다른 유닛이 그중 하나를 바꾸면 이 계약의 입력 해시 재고정이 필요해진다. 그 범위가 R4 경로에 닿아서는 안 된다. |
| `MEDIUM` | `A-50` 공급 증거는 f564bce 시점 관측이고 현재 상태 관측이 아니다. 두 시점을 섞어 읽으면 안 된다. |
| `MEDIUM` | 5절의 판정은 전사 이전 개정을 본 것이고 전사 개정 자체는 독립 검증되지 않았다. `A-50`은 전사가 공급된 판정과 일치하는지 최종 게이트에서 확인해야 한다. |
| `MEDIUM` | 임시 작업 공간 20건의 정리 부채가 이후 문서에서 축약되면 부채가 보이지 않게 된다. |
| `LOW` | 이 유닛의 결론은 단일 사용자 로컬 참조 구현 범위에 묶여 있다. |

## 11. 다음 담당자에게

독립 검증 단계는 끝났다. 5절의 판정은 `PASS`이고 종결 후보 권고는 `ISSUED`다. 남은 것은 최종
게이트다. `A-50`은 5절의 판정과 3절의 자체 점검을 대조해 `A-50` 최종 QA 게이트 판정을 내리고,
`A-02`와 `A-00`의 `HIGH` 위험 승인자 판정을 받은 뒤, `USER`의 최종 QA 승인을 요청하라. 저장소 밖
임시 작업 공간 20건의 정리를 어느 유닛이 수행할지도 함께 판정하라. 커밋·푸시·병합은 `USER`의
명시 승인 이후에만 진행하고, 이 유닛에 대한 호스티드 CI는 그 이후에야 관측된다.
