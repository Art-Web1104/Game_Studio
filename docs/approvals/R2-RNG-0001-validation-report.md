# R2-RNG-0001 검증 보고서

- 작업: `R2-RNG-0001`
- 대표 산출물: `studio_core/rng.py`
- 버전: `1.0.0` **후보** (`artifacts/R2-RNG-0001-artifact.json` 상태 `SUBMITTED`, `approved_at: null`)
- 위험 등급: `HIGH`
- 문서 상태: `READY_FOR_REVIEW` — 최종 QA 게이트 판정 아님
- 인코딩: UTF-8

이 보고서는 **실제로 관측된 사실만** 기록한다. 수행되지 않은 검토나 승인은 수행된 것으로
표기하지 않으며, 통과한 자동 검증이 인간 게이트 판정을 대체하지 않는다.

## 0. 이 문서가 주장하지 않는 것

| 항목 | 사실 |
| --- | --- |
| 최종 QA 게이트 판정 | 발행되지 않음 |
| `A-50` 인간 검토 서명 | 수행되지 않음 |
| `A-02`, `A-00` 검토 서명 | 수행되지 않음 |
| `USER` 최종 승인 | 수행되지 않음 |
| 버전 `1.0.0` 확정 | 아님. 승인 시 확정되는 **후보** 버전 |
| 상용 일정·출시일 | `R5` 이전이므로 확정하지 않음 |

## 1. 검증 수행 주체

검증 재현(replay)은 **Codex 콘솔**에서 수행되었다. 이 재현의 성격을 정확히 남긴다.

- Codex 콘솔은 저장소의 표준 검증 명령을 **독립적으로 재실행**한 기술적 재현자였다.
  구현 콘솔이 보고한 수치를 그대로 옮긴 것이 아니라 명령을 다시 실행해 결과를 얻었다.
- Codex 콘솔은 **`A-50` QA Lead 인간 검토자로서 행동하지 않았고, 그 역할을 사칭하지 않았다.**
  자동화된 재현은 `AGENTS.md`가 요구하는 "생성자와 최종 검증자의 분리" 중 기술적 재현 부분만
  충족하며, 인간 검토 서명과 게이트 판정은 여기에 포함되지 않는다.
- 따라서 아래 3절의 모든 `PASS`는 **자동 검증의 통과**이지 **검토 승인**이 아니다.

## 2. 검증 대상 범위

`tasks/R2-RNG-0001.json`의 `deliverables` 전체와 그에 연결된 계약·스키마·픽스처·감사 기록이
대상이다. 데이터베이스 격리, 실제 네트워크 재접속, 부하, 보안 침투 시험은 `AC-012`에 따라
이 작업의 범위 밖이며 후속 유닛으로 명시 이월되었다(6절).

## 3. 관측된 검증 결과

| # | 검증 | 결과 | 관측 내용 |
| --- | --- | --- | --- |
| 1 | `python scripts/validate_baseline.py` | `PASS` | 기준선 전 단계 통과. `validate_r2_rng` 단계 포함 |
| 2 | `python -m unittest discover -s tests -v` | `PASS` | 최신 재현에서 **213개 테스트 전부 통과**, 실패·오류 0건 |
| 3 | `python -m compileall -q studio_core scripts tests` | `PASS` | 구문 오류 없음 |
| 4 | 차이(diff) 점검 | `PASS` | 작업 트리 변경이 `tasks/R2-RNG-0001.json`의 산출물 목록과 롤백 계약이 열거한 파일 집합에 국한됨. 무관한 사용자 변경과 기존 승인 산출물의 의도치 않은 변경 없음 |
| 5 | 평문 비밀값 스캔 | `PASS` | 유일한 일치는 `tests/test_collaboration.py`의 `SecretHygieneTests`가 탐지기 동작을 증명하기 위해 런타임에 조립하는 **의도된 합성 탐지기 픽스처**뿐이다. 실제 자격증명·키·토큰·개인정보는 발견되지 않았다 |
| 6 | 정규 LF/CRLF 무결성 시험 | `PASS` | `tests/test_integrity.py` 전 항목 통과 |
| 7 | Task Contract `READY` 스키마 검증과 위임 게이트 | `PASS` | `contracts/task.schema.json` 직접 검증, `evaluate_delegation`이 `DELEGATED` 반환 |
| 8 | 게이트 위반·보존·발행·회수 4개 감사 이벤트 | `PASS` | `audit/events/R2-RNG-0001-events.json` 스키마 유효, 해시 연결 성립 |
| 9 | 무편향 매핑 전수 증명 | `PASS` | 256 바이트 도메인에서 37개 포켓 각 6개(채택 222), 거부 34개 |
| 10 | 독립 통계 인증 | `PASS` | 균등성·직렬 독립성·거부율 3종 검정. `studio_core/rng_stats.py`는 RNG 구현 모듈을 임포트하지 않음 |
| 11 | Artifact `content_hash` 대조 | `PASS` | 선언 해시가 `studio_core/rng.py`, `studio_core/rng_stats.py`, `games/roulette/rng-draw-record.schema.json`의 실측 정규 해시와 일치 |
| 12 | 독립 읽기 전용 코드 검토(`code-reviewer`) | `PASS` | 지적 12건 전건 반영. 이는 **에이전트 검토**이며 인간 검토 서명이 아니다 |

### 3.1 정규 LF/CRLF 무결성에 대한 보충

Artifact Contract는 `content_hash`를 `repo://` 경로에 묶는다. Windows 체크아웃의
`core.autocrlf=true`가 같은 Git blob을 CRLF로 물질화하면, 아무도 건드리지 않은 파일에 대해
무결성 검사가 변조를 보고한다. `studio_core/integrity.py`는 텍스트를 Git blob과 동일한 LF
정규형으로 환원한 뒤 해싱하고, `.gitattributes`의 `* text=auto`가 Git 쪽 정규화를 고정한다.

`tests/test_integrity.py`는 양방향을 짝지어 검증하며 전부 통과했다.

- LF와 CRLF 표현이 같은 다이제스트를 낸다. 정규형은 **LF 형태**이며 Linux 체크아웃이 계산하는
  값과 같다.
- 단독 CR은 보존된다. Git이 CRLF 쌍만 변환하므로, 단독 CR을 접으면 서로 다른 파일이 같은
  해시를 갖게 된다.
- 이진 콘텐츠는 정규화하지 않고 바이트 그대로 해싱한다. NUL 스니핑 창 규칙도 Git과 맞춘다.
- 정규화를 재현할 수 없는 모호한 바이트열(UTF-8이 아니고 NUL도 없는 경우)은 추측하지 않고
  `IntegrityError`로 **실패 폐쇄**한다.
- 줄 끝 허용이 내용 편집 허용으로 번지지 않는다. 문자 수정, 추가, 삭제, 순서 변경, 빈 줄 추가는
  두 인코딩 모두에서 해시를 바꾼다.
- 정규 다이제스트가 `git show HEAD:<path>`가 내보내는 실제 blob의 다이제스트와 일치한다.

## 4. 게이트 위반과 회수

이 작업의 구현은 **절차 위반 위에서 시작되었다.** 그 사실은 은폐되거나 소급 정당화되지 않았다.

- 이전 세션이 `READY` Task Contract 없이 `studio_core/rng.py`를 작성해 `CLAUDE.md` Required
  workflow 2항과 `AGENTS.md` Mandatory workflow 1항을 위반했다. RNG는 정책상 `High` 위험 영역이다.
- 회수는 초안을 **먼저 측정·보존한 뒤** 진행했다. 회수 시점 지문은 `27631` bytes, `713` 줄,
  sha256 `aedfacb4...78d8591`이며 `tasks/R2-RNG-0001.json`의 `inputs[]`에
  `recovered://studio_core/rng.py@pre-task-draft`(`0.1.0-draft`)로 등록되어 있다.
- 계약 발행 직후 착수 시점 Handoff(`BLOCKED`, 표준 명령 `NOT_RUN`)로 기준선을 실행했고
  **예상대로 실패했다**(`unsupported readiness 'BLOCKED'`). 검증기가 미완료 작업을 통과시키지
  않는다는 것이 그 실행의 증거다. 구현 재개는 그 이후에만 이루어졌다.
- 위반·보존·발행·회수 4개 이벤트가 해시 연결된 상태로 `audit/events/R2-RNG-0001-events.json`에
  남아 있고, 기록을 지우면 기준선이 실패한다.
- 상세 기록: `docs/operations/R2-RNG-0001-recovery.md`.

**절차 위반 자체는 이 보고서의 어떤 `PASS`로도 상쇄되지 않으며, `A-50`과 사용자의 판단 대상이다.**

## 5. 미해결 위험

`handoffs/R2-RNG-0001-handoff.json`의 `known_risks` 전건이며 축소하지 않았다.

| 심각도 | 위험 | 소유 |
| --- | --- | --- |
| `HIGH` | 이전 세션의 `READY` 게이트 위반. 초안을 보존·기록 후 계약 아래로 회수했고 위반 사실은 감사 체인에 남아 있다. 절차 위반은 소급 정당화되지 않는다 | `A-20` |
| `HIGH` | RNG 변경은 정책상 High 위험이다. `A-50`, `A-02`, `A-00`의 독립 검토 서명과 최종 QA 게이트가 발행되지 않았으므로 이 작업은 완료로 표기될 수 없다 | `A-50` |
| `MEDIUM` | 엔진 상태가 비내구적이다. 락은 한 프로세스 안의 경쟁만 막고, 재시작하면 모든 `request_id`를 잊어 같은 라운드에 두 번째 권위 결과가 생길 수 있다. 내구 저장소 이전에는 이 엔진을 멱등성의 기록 원본으로 쓰면 안 된다 | `A-02` |
| `MEDIUM` | `audit_event_ref`가 전역 유일하지 않다. 명시적 싱크 없이 만든 엔진마다 순번이 1부터 다시 시작하므로 두 테이블이 같은 참조를 발행할 수 있다. 감사 체인은 9999 이벤트에서 세그먼트 분할 없이 실패 폐쇄된다 | `A-02` |
| `MEDIUM` | `games/roulette/rng-contract.yaml`의 `interface.input`이 선언한 `protected_seed_reference`를 `DrawRequest`가 받지 않고 엔진이 서버측에서 유도한다. 서버 권위 관점에서 더 강한 선택이지만 계약 문구와의 편차이므로 `A-02`·`A-20`의 계약 개정 판단이 필요하다. R1 승인 산출물을 일방적으로 수정하지 않았다 | `A-20` |
| `MEDIUM` | R1이 R2로 이월한 기술 위험 3건 중 2건(데이터베이스 격리·동시성·장애 복구, 실제 네트워크 재접속·부하·보안 침투 시험)이 이 작업 범위 밖으로 열려 있다 | `A-02` |
| `LOW` | `proof_hash`는 변조 탐지 바인딩이며 커밋-공개 방식의 사용자 검증 가능 공정성 증명이 아니다. 도입 여부는 미결이다 | `A-20` |

### 5.1 미결 결정

- 커밋-공개 방식의 사용자 검증 가능 공정성 증명을 R2에 포함할지 여부.
- 감사 체인의 내구 저장소, 격리 수준, 장애 복구 방식.
- 연결 증거와 통계 인증의 재검증 주기.

## 6. 범위 밖으로 이월된 항목

`AC-012`에 따라 이 작업에서 수행하지 않았다: 데이터베이스 격리 수준, 실제 네트워크 재접속,
부하, 보안 침투 시험. 후보 유닛의 범위 초안은 `docs/operations/R2-followup-units.md`에 있으며
그 문서는 Task Contract가 아니고 착수 허가도 아니다. 현재 상태는 `docs/status/R2-STATUS.md`.

## 7. 롤백 요약

커밋과 푸시를 수행하지 않았으므로 **작업 트리 복원만으로 완전 복구된다.** 완전 롤백의 목표
상태는 "초안 이전"이 아니라 "위반 이전", 즉 커밋 `06331a4`이다.

1. 이 작업의 신규 파일을 삭제한다: `tasks/R2-RNG-0001.json`,
   `artifacts/R2-RNG-0001-artifact.json`, `handoffs/R2-RNG-0001-handoff.json`,
   `studio_core/rng.py`, `studio_core/rng_stats.py`, `studio_core/integrity.py`,
   `games/roulette/rng-draw-record.schema.json`,
   `games/roulette/fixtures/rng-draw-record.example.json`, `tests/test_rng.py`,
   `tests/test_integrity.py`, `audit/events/`, `.gitattributes`,
   `docs/games/R2-rng-csprng.md`, `docs/operations/R2-RNG-0001-recovery.md`,
   `docs/operations/R2-followup-units.md`, `docs/approvals/R1-evidence-closure.md`,
   `docs/approvals/R2-RNG-0001-validation-report.md`, `docs/status/R2-STATUS.md`.
2. 수정 파일을 `06331a4` 상태로 되돌린다: `scripts/validate_baseline.py`,
   `studio_core/__init__.py`, `docs/approvals/R1-checklist.md`,
   `docs/status/R1-MOBILE-STATUS.md`.
3. `python scripts/validate_baseline.py`와 `python -m unittest discover -s tests -v`를 재실행해
   R1 기준선이 그대로 통과하는지 확인한다.

`studio_core/rng.py`는 미추적 상태로 회수되었으므로 커밋 이력에 복원 대상이 없고, 회수 시점
내용의 sha256과 규모는 `docs/operations/R2-RNG-0001-recovery.md`에 보존되어 있다.

## 8. 다음 담당자에게 보내는 단일 요청

**실제 `A-50` QA Lead 또는 사용자가 직접 이 보고서와 감사 체인을 검토하고, 표준 검증 두 명령을
자신의 환경에서 재실행한 뒤, `R2-RNG-0001`에 대한 최종 QA 게이트 판정(승인 또는 반려)을
사람 이름으로 발행하라.** 자동 재현과 에이전트 검토는 이 판정을 대체하지 않으며, 그 판정 전까지
버전 `1.0.0`은 후보이고 작업은 완료가 아니다.
