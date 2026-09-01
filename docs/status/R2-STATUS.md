# R2 상태 요약

- 대상: R1 검증 보고서가 R2로 이월한 기술 위험
- 문서 성격: 상태 요약. Task Contract도, 착수 허가도, 게이트 판정도 아니다.

이 문서는 일정, 기간, 마감, 순번, 출시일을 정하지 않는다. `AGENTS.md` Non-negotiable rules와
`agents/registry.yaml`의 `production_schedule_policy: prohibited_before_r5`에 따라 상용 제작
일정과 출시일은 `R5` 승인 이후에만 확정한다. 아래의 선행 관계는 기술적 의존성이지 일정이 아니다.

## 상태 표

| 이월 위험 | 상태 | 유닛 |
| --- | --- | --- |
| 생산용 CSPRNG 추첨 경계와 독립 통계 검증 | `CLOSED_PENDING_REVIEW` | `R2-RNG-0001` (계약 발행됨) |
| 데이터베이스 격리 수준과 동시성·장애 복구 | `CLOSED_PENDING_REVIEW` | `R2-DBC-0002` (계약 발행됨) |
| 실제 네트워크 재접속과 라운드 연속성 | `OPEN` | `R2-NET-0003` (후보, 계약 없음) |
| 부하와 성능 특성 | `OPEN` | `R2-LOAD-0004` (후보, 계약 없음) |
| 보안 침투 시험 | `OPEN` | `R2-SEC-0005` (후보, 계약 없음) |

R2 경계를 소비하는 후속 유닛의 상태는 아래에 함께 적는다. 이 표의 `OPEN` 항목은 후속 유닛이
만들어졌다고 해서 닫히지 않는다.

| 후속 유닛 | 상태 | 비고 |
| --- | --- | --- |
| 내부용 로컬 플레이어블 룰렛 수직 슬라이스 | `SUBMITTED_PENDING_REVIEW` | `R4-UI-0006` (계약 발행됨) |

## CSPRNG — `CLOSED_PENDING_REVIEW`

구현과 자동 검증은 끝났고, **인간 게이트 판정만 남아 있다.** `CLOSED`가 아니라
`CLOSED_PENDING_REVIEW`인 이유가 그것이다.

- 완료된 것: OS CSPRNG 고정 엔트로피원, 거부 표본추출 무편향 매핑, 결정론 어댑터의 생산 차단,
  감사 선기록 순서, 라운드당 단일 권위 추첨과 락 직렬화, 시드·엔트로피 비기록, 추첨 기록 스키마와
  픽스처, RNG 구현을 임포트하지 않는 독립 통계 모듈, 기준선 검증기 통합, 게이트 위반 회수 기록.
- 확인된 것: 기준선 `PASS`, 단위 시험 `PASS`, `compileall` `PASS`, 차이 점검 `PASS`,
  평문 비밀값 스캔에서 의도된 탐지기 픽스처 외 일치 없음, 정규 LF/CRLF 무결성 시험 `PASS`.
  이 재현은 Codex 콘솔이 수행한 기술적 재실행이며 인간 검토 서명이 아니다.
- 남은 것: `A-50`, `A-02`, `A-00`, `USER`의 검토·승인 전건 `PENDING`. Artifact 버전 `1.0.0`은
  승인 시 확정되는 후보이고 상태는 `SUBMITTED`, `approved_at`은 비어 있다.
- 남은 위험: 게이트 위반 사실(`HIGH`), 인간 게이트 미발행(`HIGH`), 엔진 상태 비내구성(`MEDIUM`),
  `audit_event_ref` 전역 유일성 부재(`MEDIUM`), `protected_seed_reference` 계약 편차(`MEDIUM`),
  `proof_hash`의 성격(`LOW`).
- 증거: `docs/approvals/R2-RNG-0001-validation-report.md`,
  `handoffs/R2-RNG-0001-handoff.json`, `audit/events/R2-RNG-0001-events.json`,
  `docs/operations/R2-RNG-0001-recovery.md`.

## 데이터베이스 격리·동시성·장애 복구 — `CLOSED_PENDING_REVIEW`

`R2-DBC-0002` 계약 아래에서 구현과 자동 검증이 끝났고, **인간 게이트 판정만 남아 있다.**
`CLOSED`가 아니라 `CLOSED_PENDING_REVIEW`인 이유가 그것이다.

- 완료된 것: `BEGIN IMMEDIATE` 권위 경로(검사-후-행동 원자성), `SERIALIZABLE` 격리 선언,
  `journal_mode=wal`·`synchronous=full`·`foreign_keys=ON`, 유계 busy 재시도(`BEGIN`만 재시도),
  추첨·정산·감사의 단일 트랜잭션 커밋, 커밋 이전 모든 고장 지점의 완전 롤백, 재시작 후
  `request_id` 멱등성과 엔트로피 무재소비, 감사 이벤트의 전역 유일 참조와 데이터베이스 수준
  추가 전용성, 재적재 후 체인 검증, 정수 최소 단위 강제, `:memory:`·`file:` URI 거부,
  스키마 버전 고정과 자동 승격·강등 거부, 발행 SQL과 구현 문장의 일치, 기준선 검증기 통합.
- 확인된 것: 기준선 `PASS`, 단위 시험 `PASS`(`Ran 353 tests`), `compileall` `PASS`,
  평문 비밀값 스캔에서 의도된 탐지기 픽스처 외 일치 없음, 정규 LF/CRLF 무결성 대조 `PASS`.
  이 재실행은 구현자 콘솔의 기술적 재현이며 인간 검토 서명이 아니다.
- 남은 것: `A-50`, `A-02`, `A-00`, `USER`의 검토·승인 전건 `PENDING`. 독립
  `code-reviewer` 검토 미수행. Artifact 상태는 `SUBMITTED`, `approved_at`은 비어 있다.
  호스팅 CI는 커밋·푸시를 하지 않았으므로 `NOT_RUN`이다.
- 남은 위험: 인간 게이트 미발행(`HIGH`), 독립 검토 미수행(`HIGH`), SQLite 단일 노드
  참조 경계의 한계(`MEDIUM`), 동시성 증거가 로컬 스레드 범위(`MEDIUM`),
  `synchronous=full`의 쓰기 지연 미측정(`MEDIUM`), 감사 세그먼트 상한 소진 시 실패
  폐쇄(`LOW`), 호스팅 CI 이력 없음(`LOW`).
- 증거: `docs/approvals/R2-DBC-0002-validation-report.md`, `docs/games/R2-durable-state.md`,
  `handoffs/R2-DBC-0002-handoff.json`, `audit/events/R2-DBC-0002-events.json`,
  `games/roulette/durable-state-contract.yaml`.

## 내부용 로컬 플레이어블 슬라이스 — `SUBMITTED_PENDING_REVIEW`

`R4-UI-0006` 계약 아래에서 구현과 자동 검증이 끝났고, **인간 게이트 판정만 남아 있다.**
이 유닛은 R2 경계를 **소비**할 뿐이며 위 표의 `OPEN` 항목을 하나도 닫지 않는다.

- 완료된 것: 루프백 전용 표준 라이브러리 HTTP 전송, 서버 권위 단일 테이블(라운드 상태 전이,
  정수 최소 단위 잔액, 베팅 검증, 최대 책임 기준 하우스 노출 검사, 예약 기반 초과 인출 차단),
  `studio_core`의 규칙·추첨·내구 상태 경계를 수정 없이 사용하는 단일 트랜잭션 정산,
  `request_id` 멱등성과 재사용 충돌의 실패 폐쇄, 저장된 커밋 순서 기반 최근 결과, 빌드 단계
  없는 순수 HTML·CSS·JavaScript 클라이언트, 권위 필드를 실은 요청의 거부, 보안 헤더와 정적
  자산 허용 목록·경로 탐색 차단, 모든 화면·응답의 내부 프로토타입·가상 칩·현금 가치 없음 표시,
  발행 계약(`games/roulette/playable-slice-contract.yaml`)과 기준선 검증기 통합.
- 확인된 것: 기준선 `PASS`, 단위 시험 `PASS`, `compileall` `PASS`, 평문 비밀값 스캔에서
  의도된 탐지기 픽스처 외 일치 없음, 저장소 트리에 런타임 데이터베이스 파일 없음.
  이 재실행은 구현자 콘솔의 기술적 재현이며 인간 검토 서명이 아니다.
- 남은 것: `A-50`, `A-02`, `A-00`, `USER`의 검토·승인 전건 `PENDING`. 독립 `code-reviewer`
  검토 미수행. **브라우저 시각 QA `NOT_RUN`** (외부 Windows 샌드박스 기동 오류로 브라우저
  자동화를 사용할 수 없었다). 호스팅 CI `NOT_RUN`(커밋·푸시 미수행). Artifact 상태는
  `SUBMITTED`, `approved_at`은 비어 있다.
- 남은 위험: 인간 게이트 미발행(`HIGH`), 독립 검토 미수행(`HIGH`), 브라우저·화면 낭독기 사람
  검사 미수행(`HIGH`), 발주 시점 `owner_agent_id` 조정에 대한 발주자 확인 필요(`MEDIUM`),
  같은 기계 안에서는 인증·접근 제어가 없음(`MEDIUM`), 열린 라운드 베팅의 비내구성(`LOW`).
- 증거: `docs/approvals/R4-UI-0006-validation-report.md`,
  `docs/games/R4-roulette-playable-slice.md`, `handoffs/R4-UI-0006-handoff.json`,
  `audit/events/R4-UI-0006-events.json`, `games/roulette/playable-slice-contract.yaml`,
  `apps/roulette_web/README.md`.

이 유닛은 운영 배포 후보가 아니고, 네트워크 재접속·부하·침투 시험·수익화·출시 일정 중 어느
것도 수행하거나 확정하지 않는다.

## 네트워크 재접속과 라운드 연속성 — `OPEN`

계약 없음. 재접속이 서버 권위 라운드 상태만을 근거로 복구되는지, 베팅 마감 이후의 베팅을
되살리지 못하는지, 정산 통지 유실 후 이중 지급이 없는지가 대상이다. 내구 상태가 필요하므로
기술적으로 데이터베이스 유닛 뒤에 온다.

## 부하와 성능 특성 — `OPEN`

계약 없음. 동시 라운드·동시 플레이어 부하에서 정산 정확성과 감사 완전성이 유지되는지, 추첨
직렬화 락이 만드는 대기 특성이 어떤지를 **관측**한다. 용량 목표치(SLO)는 이 범위에서 확정하지
않는다. 목표치는 제작 규모 결정에 종속되고 그 결정은 `R5` 이전에 하지 않는다.

## 보안 침투 시험 — `OPEN`

계약 없음. 대상 표면과 허가 범위를 먼저 문서로 확정하고 사용자 승인을 받은 뒤에만 수행한다.
`policies/security.yaml`은 기본 거부이며 시험 자체가 승인 없이 시작될 수 없다. 클라이언트 권위
위조, 베팅 마감 우회, 정산 재요청, 감사 이벤트 위조·삭제, 시드 참조 역추적이 대상이고, 운영
환경 대상 시험·외부 대상 시험·탐지 회피는 범위 밖이다. 앞의 유닛들이 만든 표면을 대상으로
하므로 기술적으로 마지막이다.

## 이 문서가 만들지 않는 것

- Task Contract, 착수 허가, 예산 배정
- 일정, 기간, 마감, 출시일, 릴리스 약속
- `A-50` 또는 사용자의 최종 QA 게이트 판정
- 후보 식별자에 대한 선점. 실제 계약 발행 시 식별자는 재확인한다.

`OPEN` 항목을 작업으로 바꾸려면 `contracts/task.schema.json`에 유효한 `tasks/<unit_id>.json`을
`READY`로 발행하고, 같은 식별자의 Artifact Contract와 Handoff Packet을 함께 만들어야 한다.
`scripts/validate_baseline.py::validate_collaboration`이 셋을 함께 요구한다.
