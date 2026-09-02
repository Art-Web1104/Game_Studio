# R2-SEC-0005 검증 보고서

- 작업: `tasks/R2-SEC-0005.json` (`READY`, 소유자 `A-02`, 위험 `HIGH`)
- 계약: `games/roulette/security-verification-contract.yaml`
- 설계 문서: `docs/games/R2-security-verification.md`
- 하네스: `scripts/verify_r2_security.py`
- 시험: `tests/test_security_verification.py`
- 감사 기록: `audit/events/R2-SEC-0005-events.json`
- 작성자: `A-02` (구현자). **이 문서는 구현자의 자체 점검 기록과 `A-20`이 제출한 독립 구현
  검증 증거의 기록이며, 어느 쪽도 최종 QA 승인이 아니다.** 2절부터 6절까지는 `A-02`의 자체
  점검이고, 7절은 `A-20`이 수행한 독립 검증을 `A-02`가 기록한 것이다.

## 1. 무엇을 주장하고 무엇을 주장하지 않는가

주장한다: 아래 2절과 3절에 적은 실행이 실제로 일어났고 결과가 적힌 그대로였다는 것.

주장하지 않는다: 이 표면이 안전하다는 것. 유계 실행에서 55건의 사례가 성립했다는 사실은 그
사례들이 성립했다는 뜻일 뿐이다. 실행 상한(사례 64, HTTP 요청 128, 벽시계 60초, 페이로드
8192바이트)은 안전 경계이지 보안 성숙도 목표가 아니며, 이 문서를 인용하는 어떤 문서도 그
숫자를 충분성의 근거로 써서는 안 된다.

또한 주장하지 않는다: `A-50`의 최종 QA 게이트 판정, `A-00` 게이트, `USER`의 최종 QA 승인,
호스티드 CI 관측, 운영 준비 완료. 전부 `NOT_RUN`이며 8절이 그 상태다.

`A-20`의 독립 구현 검증은 수행되었고 7절에 별도로 기록되어 있다. 그 절의 수치는 `A-20`이
제출한 관측값이며, 이 문서의 작성자 `A-02`는 그 검증을 수행하지 않았고 그 판정을 자기 것으로
주장하지 않는다. `A-20`의 판정은 구현에 대한 독립 검증이며 위에 적은 최종 게이트 중 어느
것도 대신하지 않는다.

## 2. 유계 검증 실행

`python scripts/verify_r2_security.py`, 기본 설정(호스트 `127.0.0.1`, 포트 `0`, 벽시계 30초).

| 항목 | 값 |
| --- | --- |
| 실행 사례 | 55 / 계획 55 / 상한 64 |
| HTTP 요청 | 44 / 계획 44 / 상한 128 |
| 페이로드 상한 | 8192바이트 (`MAX_BODY_BYTES` 이하) |
| 성립한 검증 항목 | 5 / 5 |
| 잘못된 형식 요청 그룹 | 13 / 13 성립 |
| 발견 사항 | 0 |
| 임시 작업 공간 잔여 | 0 |
| 종료 코드 | 0 |

항목별 결과.

| 항목 | 사례 | 결과 |
| --- | --- | --- |
| `client_authority_forgery_denial` | 15 | 전부 성립. 선언 필드 13개 전수 + 최상위 1 + 리스트 중첩 1 |
| `betting_phase_lock_bypass_denial` | 8 | 전부 성립. 거부 6건 모두 스냅숏 무변화 |
| `idempotency_and_settlement_replay_safety` | 8 | 전부 성립. 제출 3, 신규 커밋 1, 재생 2, 재생 중 엔트로피 소비 0 |
| `audit_event_tamper_and_delete_detection_on_copy` | 5 | 전부 성립. 사본 3개, 원본·저장소 감사 기록 해시 불변 |
| `seed_reference_confidentiality` | 6 | 전부 성립. 문서 8개 검사, 엔트로피 재료 0 |

정산 대사: 플레이어 잔액 델타와 원장 플레이어 델타가 정수 최소 단위로 일치했고, 응답과 원장
어디에도 부동소수가 없었으며(0건), 재적재한 감사 체인의 문제도 0건이었다. 추첨 기록 2건,
정산 거래 2건이 커밋되었다.

## 3. 첫 실행이 낸 실패와 그 처리 — 지우지 않는다

탐지기 교정 이전의 **첫 하네스 실행은 종료 코드 1로 끝났다.** `SEC-SEED-01`이 성립하지 않았고
하네스는 `HIGH` 심각도 발견 사항 1건(`R2-SECFIX-CANDIDATE-001`)을 기록했다.

조사 결과 그 실패의 원인은 관측 대상 런타임이 아니라 하네스 탐지기의 설계였다.
`studio_core.rng.PROHIBITED_RECORD_FIELDS`에는 일반 명사 `state`가 들어 있는데, 추첨 기록에서
`state`는 내부 엔트로피 상태를 뜻하지만 API 응답 봉투에서 `state`는
`games/roulette/playable-slice-contract.yaml`이 `GET /api/state`에 요구하는 라운드 스냅숏이다.
이름만 보고 두 경우를 함께 막은 탓에 **필수 필드를 유출로 보고한 것**이며, 런타임에는 결함이
없었다.

처리 방식은 다음과 같았다. **운영 런타임 코드는 한 줄도 바꾸지 않았다.** 대신 하네스의 응답
검사에서 `state`를 이름 기반 금지 목록에서 제외하고, 그 대신 `state`가 최상위 봉투 경로
`$.state` 한 곳에만 나타나는지를 경로 기반으로 단언하도록 교정했다. 더 깊은 위치의 `state`는
여전히 걸린다. 이 예외와 그 이유는 계약의 `confidentiality.state_key_exception`에 명시되어
있고, 시험 `DetectorTestCase.test_key_path_detector_distinguishes_the_envelope_from_a_nested_state`가
봉투와 중첩 상태를 실제로 구분하는지 확인한다.

이 실패는 감사 기록 `AE-R2SEC-0005`에 `FAIL`로 남아 있고 삭제하지 않는다. 실패한 검증을
통과로 적지 않는 것과 같은 이유로, 실패했던 사실을 없던 일로 만들지도 않는다.

## 4. 발견 사항

교정 이후 실행에서 **발견된 취약점은 없다.** 따라서 이 유닛이 넘기는 개선 Task Contract
후보(`R2-SECFIX-CANDIDATE-<n>`)도 없다.

발견 사항이 생겼을 경우의 처리 방식은 계약이 이미 고정해 두었고 코드로 구현되어 있다. 각
발견은 정제된 기록(항목, 심각도, 사례 식별자, 기대, 관측된 코드와 건수)만 남기고, 재현 가능한
공격 페이로드 전문, 실제 비밀값, 개인정보는 남기지 않는다. 그리고 각 발견은
`R2-SECFIX-CANDIDATE-<n>` 후보 식별자를 얻는다. 그 식별자는 승인 주체가 채택할 수 있는
**후보**이지 이 유닛에 수정 권한을 주는 승인이 아니다.
`DetectorTestCase.test_a_failed_case_becomes_a_sanitized_finding_and_never_a_repair`가 그
경로를 실제로 실행해 확인한다.

## 5. 시험과 정적 점검

| 실행 | 결과 |
| --- | --- |
| `python -m unittest tests.test_security_verification -v` (집중) | 86건 PASS |
| 같은 집중 시험 반복 실행 | 동일하게 PASS |
| `python -m compileall -q scripts tests studio_core apps` | PASS |
| `python scripts/scan_secrets.py` | PASS (216개 파일, 평문 비밀값 0건) |

집중 시험이 확인하는 것 중 특히 중요한 네 가지.

- **프리플라이트 거절이 자원보다 먼저다.** 하네스 모듈의 `tempfile`, `threading`, `os`,
  `shutil`, `sqlite3`, `http`, `hash_file`, `open_table`, `create_server`,
  `serve_in_background`를 전부 덫으로 바꾼 상태에서 상한 초과 설정 네 종류, 계획 초과 설정,
  비정수 설정, 비루프백 IP 리터럴 6종, 이름 문자열 5종, 고정 포트를 각각 거절시킨다. 거절 전후
  임시 작업 공간 집합이 동일함도 함께 단언한다.
- **이름 해석이 없다.** 정적으로는 하네스 구문 트리에 해석 호출이 0건이고, 동적으로는
  `socket.getaddrinfo`·`gethostbyname`·`getfqdn`·`gethostname`을 전부 예외를 던지도록 바꾼
  상태에서도 같은 거절이 나온다.
- **탐지기가 실제로 작동한다.** 검증기의 탐지기들에 걸려야 할 재료(긴 16진 열, 바이트 이스케이프
  열, 키에 할당된 엔트로피 재료, 트레이스백, SQLite 메시지, 중첩된 `state`, 통화 부동소수)를
  심어 잡히는지, 깨끗한 입력(공개된 `sha256:` 다이제스트, `entropy-ref://` 참조)이 안 잡히는지를
  양쪽으로 확인한다. 절대 발화하지 않는 탐지기는 고무도장이기 때문이다.
- **동결 경로가 무변경이다.** 계약이 고정한 31개 경로 전부의 정규 LF 해시를
  `studio_core.integrity.hash_file`로 재계산해 선언값과 대조한다.

## 6. 두 표준 명령

| 명령 | 결과 |
| --- | --- |
| `python scripts/validate_baseline.py` | PASS |
| `python -m unittest discover -s tests -v` | PASS (792건, 4건 건너뜀, 실패 0, 오류 0) |

기록 절차를 밝혀 둔다. 이 저장소의 완료 게이트는 자기 참조 구조를 갖는다.
`scripts/validate_baseline.py`의 `validate_collaboration` 단계는 `tasks/` 아래 모든 계약의
Handoff Packet에 `READY_FOR_REVIEW` 이상의 readiness와 두 표준 명령의 `PASS` 기록을 요구하므로,
Handoff가 `REWORK_REQUIRED`인 동안에는 두 명령이 반드시 실패한다. 그래서 순서를 다음과 같이
했다. 먼저 게이트와 무관한 모든 시험을 통과시키고, 그 상태에서 Handoff를 제안된
`READY_FOR_REVIEW`로 갱신한 뒤, **그 정확한 상태에 대해** 두 명령을 실제로 실행했다. 둘 중
하나라도 실패했다면 즉시 `REWORK_REQUIRED`로 되돌리고 `FAIL`로 기록할 예정이었다. 둘 다
통과했으므로 `READY_FOR_REVIEW`를 유지하고 관측된 건수를 그대로 적었다. 수행하지 않은 검증에
`PASS`를 적지 않았고, 통과하지 않은 실행을 `PASS`로 부르지도 않았다.

증거 문서와 해시가 확정된 뒤 두 명령을 한 번 더 실행해 같은 결과임을 확인했다. 7절의 증거를
이 문서와 감사 기록에 기록하면서 두 파일의 정규 LF 해시가 다시 바뀌었으므로, 아티팩트의 구성
요소 해시를 재계산해 갱신한 뒤 같은 명령들을 한 번 더 실행했다. 그 재실행은 `A-02`의 자체
점검이며 `A-20`의 독립 검증이 아니다.

## 7. `A-20` 독립 구현 검증 — 공급된 증거의 기록

이 절은 `A-20`이 Codex 콘솔에서 독립적으로 수행한 구현 검증의 결과를 기록한다. **검증자는
`A-20`이고 기록자는 `A-02`다.** `A-02`는 이 검증을 수행하지 않았고, 아래 수치는 전부 `A-20`이
제출한 관측값이다. `A-20`은 이 검증을 6절까지의 상태, 즉 이 절이 기록되기 이전의 증거 문서에
대해 수행했다.

### 7.1 소스 수준 검토

`A-20`은 다음 지점을 소스 수준에서 검토했고 조치가 필요한 문제를 발견하지 않았다.

- 프리플라이트 거절이 자원 생성보다 앞선다는 성질
- 루프백 리터럴 멤버십 판정과 이름 해석의 부재
- HTTP 응답 처리와 연결 종료
- 서버 작업 스레드의 등록·합류와 스레드별 SQLite 자원 반환
- 감사 조작이 사본에만 적용되고 원본 해시가 보존된다는 성질
- 멱등성의 정확히 한 번 단언
- 정리 이후 임시 작업 공간의 부재를 긍정적으로 확인하는 점

### 7.2 `A-20`이 재실행한 명령

| 명령 | `A-20` 관측 결과 |
| --- | --- |
| `python scripts/verify_r2_security.py` | 종료 코드 0. 사례 55/55, HTTP 요청 44/44, 다섯 항목 성립, 잘못된 형식 13건 성립, 발견 0건. 임시 작업 공간 `ts-studio-r2-sec-*` 실행 전 0개, 실행 후 0개 |
| `python -m unittest tests.test_security_verification -v` | 종료 코드 0. 86건, 실패 0, 오류 0, 건너뜀 0 |
| `python scripts/validate_baseline.py` | 종료 코드 0. 20단계 `PASS`, 0단계 `FAIL` |
| `python -m unittest discover -s tests -v` | 종료 코드 0. 792건, 4건 건너뜀, 실패 0, 오류 0 |
| `python -m compileall -q scripts tests studio_core apps` | 종료 코드 0 |
| `python scripts/scan_secrets.py` | 종료 코드 0. 216개 파일, 0건 |

### 7.3 무결성과 경계

- 아티팩트가 선언한 구현 구성 요소 6종의 해시를 `A-20`이 직접 재계산해 전부 일치했다.
- 계약이 고정한 31개 입력 해시가 통과한 집중 시험의 대조 경로로 전부 확인되어 일치했다.
- `evaluate_independent_verification(handoff, console=codex, verifier_agent_id=A-20)`이
  `allowed=True`와 `VERIFIABLE`을 반환했다.
- `git status` 기준으로 이 유닛의 신규·미추적 파일은 정확히 9건이었고 추적 중인 기존 파일의
  수정은 0건이었다.
- 이 유계 로컬 범위 안에서 `A-20`이 발견한 런타임 보안 문제는 0건이다.

### 7.4 이 검증이 무엇이 아닌가

`A-20`의 판정은 **구현에 대한 독립 검증**이며 그 이상이 아니다. `A-50`의 최종 QA 게이트,
`A-00` 게이트, `USER`의 최종 QA 승인, 호스티드 CI 관측, 운영 준비 판정, 커밋·푸시·병합은 이
검증으로 대체되지 않고 전부 수행되지 않은 상태로 남아 있다. 8절이 그 상태다. 또한 이 절은
2절과 8절의 유보를 철회하지 않는다. 유계 실행이 전수가 아니라는 사실은 독립 검증자가 같은
실행을 재현했다고 해서 달라지지 않는다.

## 8. 아직 수행되지 않은 것

| 판정 | 상태 |
| --- | --- |
| `A-20` 독립 구현 검증 | `PASS` (7절, 구현 독립 검증에 한함) |
| `A-50` 최종 QA 게이트 | `NOT_RUN` |
| `A-00` 게이트 | `NOT_RUN` |
| `USER` 최종 QA 승인 | `NOT_RUN` |
| 호스티드 CI 관측 | `NOT_RUN` |
| 운영 준비 판정 | `PENDING` |
| 커밋·푸시·병합 | `NOT_RUN` |

## 9. 남은 위험

- 이 유닛의 결과는 **단일 사용자 루프백 참조 구현**에 대한 것이다. 다중 사용자 신원·세션 분리가
  도입되면 인증·인가·세션 계열 표면이 새로 생기고, 이 문서는 그 표면에 대해 아무것도 말하지
  않는다.
- 유계 실행은 정의상 전수가 아니다. 55건의 결정론적 사례는 계약이 선언한 다섯 항목을 겨냥한
  것이며, 선언되지 않은 공격 표면은 검증되지 않았다.
- 감사 조작 검증은 사본 경계를 코드로 강제한다. 그 경계가 이후 변경으로 느슨해지면 원본이
  위험해지므로, 원본 해시 불변 단언은 앞으로도 유지되어야 한다.
- 발견과 개선 사이의 시간 간격은 이 유닛이 만드는 구조적 성질이다. 이번에는 발견 사항이 0건이라
  간격이 열리지 않았지만, 이후 실행에서 발견이 생기면 개선 Task Contract의 발행 책임은 승인
  주체에 있다.

## 10. 변경 파일

신규 9건, 기존 파일 수정 0건.

- `tasks/R2-SEC-0005.json`
- `artifacts/R2-SEC-0005-artifact.json`
- `handoffs/R2-SEC-0005-handoff.json`
- `games/roulette/security-verification-contract.yaml`
- `scripts/verify_r2_security.py`
- `tests/test_security_verification.py`
- `docs/games/R2-security-verification.md`
- `docs/approvals/R2-SEC-0005-validation-report.md`
- `audit/events/R2-SEC-0005-events.json`

`scripts/validate_baseline.py`는 무변경이다. 이 유닛은 기준선 검증기에 단계를 추가하지 않았고,
계약과 구현의 대조는 신규 시험 파일 안에서 수행했다.
