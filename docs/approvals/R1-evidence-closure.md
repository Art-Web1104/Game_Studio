# R1 증거 종결 기록

- 작성일: `2026-09-01`
- 작업: `R2-RNG-0001`
- 대상: `docs/approvals/R1-checklist.md`의 "후속 승인" 5개 항목
- 상태: `EVIDENCE_RECORDED / HUMAN_APPROVAL_PENDING`

## 0. 이 문서가 하는 일과 하지 않는 일

이 문서는 R1 후보에 대해 **자동 검증으로 실제 확인된 사실**을 역할별로 정리한다.

이 문서는 승인 기록이 **아니다**. `A-10`, `A-20`, `A-02`, `A-50`, `A-00`의 검토 서명은 수행되지
않았고, 이 문서는 그것을 수행된 것으로 표기하지 않는다. `docs/approvals/R1-checklist.md`의
후속 승인 체크박스는 전부 미체크 상태로 유지되며, `scripts/validate_baseline.py::validate_r2_rng`가
그 섹션에 체크된 항목이 생기면 기준선을 실패시킨다. 즉 이 정직성 요건은 문장이 아니라 검사다.

`AGENTS.md` Authority order와 `operations/collaboration.yaml`의 `separation_of_duties`에 따라,
구현을 생성한 주체는 자신의 산출물에 대한 최종 게이트를 발행할 수 없다. 아래 결론은 생성자가
수집한 증거이며, 독립 검증자와 최종 게이트의 입력이지 대체물이 아니다.

## 1. 사용자 승인 (실제로 존재하는 승인)

| 항목 | 내용 |
| --- | --- |
| 승인 주체 | `USER` |
| 승인 시점 | 2026-09-01 세션 |
| 승인 범위 | `R2-RNG-0001` 작업의 착수와 수행 (생산용 CSPRNG 추첨 경계 + 독립 통계 + R1 증거 종결) |
| 승인 형태 | 세션 내 명시적 작업 지시 |
| 승인이 **아닌** 것 | R2 릴리스 게이트 통과, R1 후속 승인 5종의 대리 서명, 최종 QA 판정, 커밋·푸시 권한 |

사용자는 이 작업의 수행을 승인했다. 이는 `tasks/R2-RNG-0001.json`의 `approvers`에 `USER`가
포함된 근거이자 위임 게이트의 `required_approver` 요건을 충족하는 근거다. 최종 QA 게이트는
`operations/collaboration.yaml`의 `final_gate: [A-50, USER]`에 그대로 남아 있고, 이 작업으로
소진되지 않았다.

## 2. 역할별 증거 기반 결론

각 행의 "결론"은 실행된 검증이 뒷받침하는 범위까지만 기술한다. "승인 상태"는 모두 미서명이다.

### A-10 Design Lead — 지원 베팅·규칙 범위

- 승인 상태: `미서명 (PENDING)`
- 증거 기반 결론: 지원 베팅 13종의 유효 위치가 전수 열거·검증된다. 스트레이트 37, 스플릿 60,
  스트리트 12, 코너 22, 식스라인 11, 두즌 3, 컬럼 3, 외부 베팅 6종 각 1이며, 각 위치가
  `validate_bet`을 통과한다. 잘못된 스플릿·코너·선택 수·베팅 단위는 거부된다.
- 증거: `scripts/validate_baseline.py::validate_r1_roulette`, `games/roulette/r1-rules-extension.yaml`,
  `tests/test_baseline.py`
- 남은 판단: 규칙 **범위**가 제품으로서 적절한지는 자동 검증의 대상이 아니다. 이는 Design Lead의
  판단 사항으로 남는다.

### A-20 Engineering Lead — 원장·라운드·RNG 인터페이스

- 승인 상태: `미서명 (PENDING)`
- 증거 기반 결론: 원장은 정수 단위·합계 0·멱등 거래이며 플레이어 음수 잔액을 거부한다. 라운드는
  서버 권위 전이만 허용하고 클라이언트 전이는 거부된다. RNG 인터페이스 계약은 편향·시드 노출·중복
  추첨을 차단하도록 선언되어 있고, `R2-RNG-0001`에서 그 선언이 실제 구현·검증되었다.
- 증거: `scripts/validate_baseline.py::validate_r1_roulette`, `::validate_r2_rng`,
  `studio_core/rng.py`, `tests/test_rng.py`
- 참고: `A-20`은 `R2-RNG-0001`의 `owner_agent_id`다. 생성자는 자신의 산출물을 독립 검증할 수
  없으므로, R1 RNG 인터페이스 항목에 대한 `A-20`의 서명은 이 작업으로 대체되지 않는다.

### A-02 Platform Integrator — 보안·감사·공급자 경계

- 승인 상태: `미서명 (PENDING)`
- 증거 기반 결론: 보안 정책은 기본 거부이며 에이전트 직접 생산 접근이 차단된다. 비밀값은
  저장소·프롬프트·로그에서 금지되고 참조만 허용된다. 감사 이벤트 8종 커버리지와 불변성이
  선언되어 있으며, RNG 추첨 감사 이벤트가 해시 연결 체인으로 실제 생성·검증된다. 공급자 경계는
  ADR-0003대로 Claude 단독이고 Codex는 활성 라우트에 없다.
- 증거: `scripts/validate_baseline.py::validate_policies`, `::validate_providers`,
  `::validate_collaboration`, `::validate_r2_rng`, `studio_core/collaboration.py`
- 남은 판단: 감사 체인의 **내구성 저장소**는 아직 없다. 현재는 인메모리 참조 구현이며 후속 R2
  데이터베이스 유닛의 범위다.

### A-50 QA Lead — 수학·부정 테스트 독립 승인

- 승인 상태: `미서명 (PENDING)`
- 증거 기반 결론: 지원 베팅 전부의 RTP가 `36/37`, 하우스 엣지가 `1/37`이고, 37개 결과 전수 정산
  시 1단위 베팅의 순변화 합계가 `-1`이다. RNG 매핑의 무편향성은 표본이 아니라 256개 바이트
  도메인 전수 열거로 증명된다. 부정 경로 테스트가 실패 폐쇄 동작을 확인한다.
- 증거: `scripts/validate_baseline.py::validate_r1_roulette`, `::validate_r2_rng`,
  `tests/test_baseline.py`, `tests/test_rng.py`, `docs/approvals/R2-RNG-0001-validation-report.md`
- 남은 판단: `A-50`의 최종 QA 게이트 판정은 수행되지 않았다. `CLAUDE.md` Definition of done에
  따라 이 판정은 `A-50` 또는 인간만 발행할 수 있다.

### A-00 Game Director / 사용자 — R2 진입 승인

- 승인 상태: `미서명 (PENDING)` — 단, 1절의 사용자 작업 승인은 별도로 존재한다.
- 증거 기반 결론: R1 후보의 내부 일관성은 자동 검증으로 확인되었고, R1이 R2로 이월한 기술 위험
  3건 중 1건(생산용 CSPRNG + 독립 통계)이 `R2-RNG-0001`에서 닫혔다. 나머지 2건은 열려 있다.
- 남은 판단: R2 릴리스 게이트 진입 승인은 발행되지 않았다. R5 이전이므로 상용 제작 일정과
  출시일은 확정하지 않는다.

## 3. R1이 R2로 이월한 기술 위험의 현재 상태

| 이월 위험 | 상태 | 근거 |
| --- | --- | --- |
| 생산용 CSPRNG 구현과 독립 통계 검증 | `CLOSED_PENDING_REVIEW` | `R2-RNG-0001`, `studio_core/rng.py`, `studio_core/rng_stats.py` |
| 데이터베이스 격리 수준과 동시성·장애 복구 | `OPEN` | 이 작업 범위 밖. 후속 R2 유닛 |
| 실제 네트워크 재접속, 부하, 보안 침투 시험 | `OPEN` | 이 작업 범위 밖. 후속 R2 유닛 |

`CLOSED_PENDING_REVIEW`는 구현과 증거가 존재하고 자동 검증을 통과했으나 독립 검증과 최종
게이트가 남아 있다는 뜻이다.

## 4. 다음 담당자에게

`A-50`은 Codex 콘솔에서 `python scripts/validate_baseline.py`와
`python -m unittest discover -s tests -v`를 재실행하고, `handoffs/R2-RNG-0001-handoff.json`의
증거와 대조한 뒤 최종 QA 게이트 판정을 발행하라.
