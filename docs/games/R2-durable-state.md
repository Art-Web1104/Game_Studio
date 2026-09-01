# R2 유닛 2: 내구 상태 경계 (격리·원자성·동시성·장애 복구)

- 작업: `R2-DBC-0002`
- 계약: `games/roulette/durable-state-contract.yaml` (`DURABLE-STATE-R2`)
- 구현: `studio_core/durable_state.py`
- 스키마: `games/roulette/durable-state-schema.sql`
- 시험: `tests/test_durable_state.py`
- 검증기: `scripts/validate_baseline.py::validate_r2_durable_state`
- 위험 등급: `HIGH` (`policies/risk.yaml` — 원장·정산·감사 경로에 닿는다)

이 문서는 설계 근거를 적는다. 게이트 판정도, 일정도, 출시 약속도 아니다.

## 1. 이 유닛이 닫는 위험

`docs/approvals/R1-evidence-closure.md`가 R2로 이월한 "데이터베이스 격리 수준과 동시성·장애
복구" 항목이다. `R2-RNG-0001`이 남긴 공백은 선언이 아니라 코드에서 실측 가능한 사실이었다.

- `studio_core/rng.py`의 엔진 상태는 프로세스 메모리에만 있다. 락은 한 프로세스 안의 경쟁만
  막고, 재시작하면 모든 `request_id`를 잊는다. 같은 라운드에 두 번째 권위 결과가 생길 수 있다.
- `AuditChain`이 인메모리 참조 구현이므로 `policies/audit.yaml`의 `integrity.immutable`은
  아직 선언이지 보장이 아니었다.
- `audit_event_ref` 순번이 엔진 인스턴스마다 1에서 다시 시작해 전역 유일성이 없었다.
- 원장 멱등성이 호출자가 넘긴 키 집합에 의존했고, 동시 제출 경로는 저장소 격리 수준의 문제였다.

## 2. 경계 설계

구현은 파이썬 표준 라이브러리 `sqlite3`만 쓰는 **참조 경계**다. 외부 데이터베이스 서버도,
네트워크 클라이언트도, 운영 배포도 없다. 목적은 "저장 계층이 무엇을 보장해야 하는가"를
산문이 아니라 실행 가능한 형태로 고정해, 이후의 생산용 저장소가 시험 가능한 목표를 갖게 하는
것이다.

`rng.py`가 선언한 어떤 것도 약화하지 않는다. 추첨은 여전히 `RouletteDrawEngine`이
공개된 `EntropySource`·`AuditSink` 프로토콜 뒤에서 수행하고, 거부는 여전히
`games/roulette/rng-contract.yaml`의 실패 동작을 담은 `RngDenied`다. 잔액 산술은 여전히
`studio_core.ledger.post_transaction`을 통과하므로 R1 불변식(정수 최소 단위, 항목 합 0,
플레이어 잔액 음수 금지)은 재선언이 아니라 재사용으로 유지된다.

**데이터베이스가 기록의 원본이다.** `RouletteDrawEngine` 인스턴스는 제출 시도마다 새로 만들고
버린다. 엔진이 시도 사이에 상태를 들고 있으면 롤백된 트랜잭션 뒤에 "이 라운드는 추첨되었는가"에
대한 답이 엔진과 데이터베이스에서 갈라지고, 하필 그 갈라짐이 가장 위험한 순간에 생긴다.
권위 있는 질문(이 `request_id`는 처리되었는가, 이 라운드에 추첨이 있는가, 무효화되었는가)은
모두 커밋된 행에서만 답한다.

## 3. 격리 수준과 트랜잭션 모드

| 항목 | 값 | 근거 |
| --- | --- | --- |
| `isolation_level` | `SERIALIZABLE` | SQLite 트랜잭션이 제공하는 수준 |
| `transaction_mode` | `IMMEDIATE` | 검사-후-행동을 다른 연결·프로세스에 대해 원자적으로 만든다 |

SQLite의 위험은 낮은 격리 수준이 아니다. 위험은 **읽기로 시작한 `DEFERRED` 트랜잭션이 쓰기로
승격하지 못하고 `SQLITE_BUSY`로 실패하는 경우**다. 그때 트랜잭션은 이미 중복 검사를 마치고
판단을 내린 뒤다. 그래서 모든 권위 경로가 `BEGIN IMMEDIATE`로 연다. 쓰기 락을 중복 검사보다
**먼저** 잡으므로 검사와 행동 사이에 다른 기록자가 끼어들 수 없다.

같은 `request_id`를 서로 다른 스레드·연결에서 동시에 제출한 두 호출자는 이 락으로 직렬화된다.
진 쪽은 자기 트랜잭션 안에서 커밋된 기록을 다시 읽어 **엔트로피를 재소비하지 않고** 원본 결과를
반환한다. 이 성질은 단위 시험의 모의가 아니라 실제 스레드 동시 실행으로 증명한다
(`tests/test_durable_state.py`, 계약의 `concurrency_proved_by_real_threads`).

### 바쁨(busy) 재시도

| 항목 | 값 |
| --- | --- |
| `busy_timeout_ms` | `5000` |
| `max_busy_retries` | `5` |
| `retry_backoff_seconds` | `0.02` |

`PRAGMA busy_timeout`은 막힌 기록자를 실패시키지 않고 기다리게 한다. `MAX_BUSY_RETRIES`는
timeout이 적용되기 전에 busy가 보고되는 좁은 구간만 덮는다. **재시도는 `BEGIN`만 다시 실행한다.**
이미 열린 트랜잭션은 절대 재시도하지 않는다. 부분 적용된 권위 작업의 맹목적 재시도가 이중 정산의
발생 경로이기 때문이다. 락을 끝내 얻지 못하면 `WRITE_LOCK_UNAVAILABLE`로 실패 폐쇄한다.

## 4. 내구성 프라그마

| 항목 | 값 | 근거 |
| --- | --- | --- |
| `journal_mode` | `wal` | 기록자가 락을 잡은 동안에도 읽기를 허용한다. 재생 빠른 경로가 정산을 막지 않는다 |
| `synchronous` | `full` | WAL의 통상 짝은 `NORMAL`이지만 선택하지 않았다 |
| `foreign_keys` | `true` | SQLite에서 연결 단위 설정이므로 **모든** 연결에서 켠다 |

`synchronous=NORMAL`은 전원 손실 시 최근 커밋을 잃을 수 있다. 권위 있는 자금 이동에서
"라운드는 정산되었는데 기록이 없다"는 결과는 허용되지 않으므로 `FULL`을 택했고, 그 대가인
쓰기 지연은 이 경계에서 받아들인다. 외래키를 모든 연결에서 켜므로 존재하지 않는 감사 이벤트를
참조하는 원장 행이 생길 수 없다.

## 5. 스키마 버전과 이관

| 항목 | 값 |
| --- | --- |
| `schema_version` | `1` |
| `supported_schema_versions` | `[1]` |
| `automatic_upgrade` / `automatic_downgrade` | 둘 다 `denied` |

버전은 파일 헤더의 `PRAGMA user_version`과 `schema_meta` 테이블 행에 **함께** 기록하고 개방
시점에 둘을 대조한다. 한쪽만 고친 편집이 조용히 통과하지 않는다. 지원하지 않는 버전은
내려서 여는 대신 `SCHEMA_VERSION_UNSUPPORTED`로 거부한다. `user_version`이 0인데 이 모듈이
소유하는 테이블이 이미 있으면 `SCHEMA_STATE_AMBIGUOUS`, 헤더와 메타 행이 어긋나면
`SCHEMA_META_MISMATCH`다. 세 경우 모두 실패 폐쇄이며 자동 복구를 시도하지 않는다.

`games/roulette/durable-state-schema.sql`은 사람이 읽기 위한 사본이 아니라 구현이 실제로
실행하는 `SCHEMA_STATEMENTS`의 발행본이다. 둘이 어긋나면 검증기가 실패한다.

## 6. 데이터베이스 경로 처리

`sqlite3.connect`는 파일 이름 외의 것도 받는다. `:memory:`는 닫으면 사라지는 사설
데이터베이스를 조용히 만들고, `file:` URI는 `mode=`나 `cache=shared` 같은 매개변수로 이
문서가 선언한 내구성·격리를 바꿀 수 있다. 둘 다 코드 검토가 아니라 **개방 시점에** 거부한다.

| 항목 | 값 |
| --- | --- |
| `memory_database` | `prohibited` (`PATH_INVALID`) |
| `uri_filename` | `prohibited` (`PATH_INVALID`) |
| `connect_uri_parameter` | `false` — 연결은 항상 `uri=False` |
| `relative_path_resolution` | `anchored_to_process_cwd` |
| `parent_directory_must_exist` | `true` |
| `symlink_resolution` | `not_performed` — 호출자가 지정한 파일이 곧 대상이다 |
| `nul_byte_in_path` | `prohibited` |
| `directory_as_database` | `prohibited` |

심볼릭 링크를 해석하지 않는 것은 의도된 선택이다. 해석하면 "내가 지정한 경로"와 "실제로 쓰이는
경로"가 갈라지고, 그 갈라짐은 감사 기록에서 되짚을 수 없다.

저장소 안에는 데이터베이스 파일을 만들지 않는다. 시험과 검증기는 임시 디렉터리에만 만들고
정리하며, `tests/test_durable_state.py`가 저장소 트리에 `.sqlite3`/`.sqlite`/`.db`가 남지
않았음을 직접 확인한다.

## 7. 원자성과 장애 복구

추첨 기록·정산 원장·감사 이벤트는 **하나의 트랜잭션**으로 커밋되거나 전부 롤백된다. 주입 가능한
고장 지점은 `FAULT_STAGES`로 이름이 붙어 있다.

`after_begin` · `after_draw` · `after_ledger` · `before_commit` · `after_commit`

커밋 이전의 어느 지점에서 고장이 나든, 다시 열었을 때 남아야 하는 것은 없다. 확인하는 성질은
넷이다. 커밋된 `draw_record`·`ledger_transaction`·`ledger_entry` 행이 0건이고, 잔액이 움직이지
않았고, `ROULETTE_RNG_DRAW` 감사 이벤트가 남지 않았고, 감사 체인이 여전히 검증된다.
`after_commit` 고장은 성격이 다르다. 그 시점의 결과는 이미 권위 있는 기록이므로 롤백 대상이
아니라 재생 대상이다.

## 8. 감사 이벤트의 전역 유일성과 불변성

`audit/audit-event.schema.json`이 `event_id`를 네 자리로 고정하므로 한 세그먼트는 9999개
이벤트를 담는다(`audit_segment_size: 9999`, `max_audit_segment: 99`). 세그먼트 번호가 그
경계 이후의 전역 유일성을 유지하고, 세그먼트가 소진되면 식별자를 **재사용하지 않고** 실패
폐쇄한다. 이것이 `R2-RNG-0001`이 `MEDIUM` 위험으로 남긴 "인스턴스마다 1에서 재시작하는 순번"을
닫는다.

불변성은 애플리케이션의 약속이 아니라 데이터베이스의 제약이다. `audit_event`에는
`UPDATE`·`DELETE`를 거부하는 트리거가 있고, `ledger_transaction`·`ledger_entry`·`draw_record`도
같다. 원시 SQL로 감사 이벤트를 고치거나 지우려는 시도는 `sqlite3.IntegrityError`로 실패하며,
검증기가 실제로 두 문장을 실행해 그 사실을 확인한다. 재적재 뒤에도 해시 체인이 검증되고,
변조된 체인은 재적재 시점에 탐지된다.

## 9. 저장하지 않는 것

엔트로피 바이트, 시드 값, 거부 표본 횟수, 평문 비밀값, 부동소수점 통화, 클라이언트 권위 상태.
앞의 넷은 `INSERT` 이전에 `_reject_unstorable`이 거부하고, 정수 통화는 `typeof()` `CHECK`
제약으로 **원시 SQL을 통해서도** 들어올 수 없다. 금지 필드 이름의 원본은
`studio_core.durable_state.PROHIBITED_STORAGE_FIELDS`이며 그 앞부분은
`studio_core.rng.PROHIBITED_RECORD_FIELDS`를 재선언이 아니라 재사용한다. RNG 쪽에 금지 필드가
추가되면 이곳에서도 자동으로 거부된다.

검증기는 이것을 선언이 아니라 관측으로 확인한다. 디바이싱 규칙이 모두 수용하는 바이트로 만든
표지 값을 엔트로피원에 넣고 추첨을 수행한 뒤, 그 바이트열이 데이터베이스 **파일**에 나타나지
않음을 읽어서 확인한다.

## 10. 실패 동작 표

| 조건 | 동작 |
| --- | --- |
| 같은 `request_id`, 같은 요청 내용 | `RETURN_ORIGINAL_RESULT` |
| 같은 `request_id`, 다른 요청 내용 | `DUPLICATE_REQUEST_CONFLICT` |
| 같은 멱등키, 다른 내용 | `IDEMPOTENCY_KEY_CONFLICT` |
| 이미 추첨된 라운드 | `ROUND_ALREADY_DRAWN` |
| 무효화된 라운드 | `ROUND_VOIDED` |
| 커밋 이전 고장 | `ROLLBACK_AND_VOID_ROUND` |
| 쓰기 락 획득 실패 | `WRITE_LOCK_UNAVAILABLE` |
| 미지원 스키마 버전 | `SCHEMA_VERSION_UNSUPPORTED` |
| 엔트로피·비밀 재료 제출 | `ENTROPY_MATERIAL_DENIED` |
| 부동소수점 통화 제출 | `FLOAT_VALUE_DENIED` |

## 11. 범위 밖과 이월

이 유닛은 다음을 하지 않는다. 각 항목은 계약의 `out_of_scope`와
`docs/operations/R2-followup-units.md`에 같은 이름으로 남아 있다.

- 외부 데이터베이스 서버·관리형 서비스 도입과 운영 규모 엔진 선정
- 실제 네트워크 재접속과 라운드 연속성 — 후속 유닛 후보 `R2-NET-0003`, 상태 `OPEN`
- 부하·성능 특성 측정 — 후속 유닛 후보 `R2-LOAD-0004`, 상태 `OPEN`
- 보안 침투 시험 — 후속 유닛 후보 `R2-SEC-0005`, 상태 `OPEN`
- 운영 배포, 백업·복구 절차, WAL 체크포인트 주기, 보존 기간
- 상용 제작 일정과 출시일 (`R5` 승인 이전 확정 금지)

SQLite 참조 경계라는 선택 자체도 이월 위험이다. 이 경계는 단일 파일·단일 노드를 전제하므로
다중 노드 운영 저장소의 격리·복제 특성은 여기서 증명되지 않는다. 증명된 것은 **저장 계층이
만족해야 하는 성질의 목록과 그 시험**이며, 생산 저장소는 같은 시험을 통과해야 한다.

## 12. 인간 게이트

구현과 자동 검증이 끝났다는 것은 이 유닛이 승인되었다는 뜻이 아니다. `HIGH` 위험이므로
`A-50`, `A-02`, `A-00`의 검토와 `USER`의 최종 게이트 판정이 필요하고, 구현자는 자체 승인할 수
없다. 현재 상태는 `docs/status/R2-STATUS.md`에서 `CLOSED_PENDING_REVIEW`이며 증거는
`docs/approvals/R2-DBC-0002-validation-report.md`에 있다.
