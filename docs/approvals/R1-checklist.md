# R1 룰렛 규칙·경제 승인 체크리스트

현재 상태: `AUTOMATED_CHECKS_PASSED / R1_APPROVAL_PENDING`

## 자동 검증

- [x] 0~36 포켓과 유럽식 단일 제로 휠이 정확하다.
- [x] 지원 베팅 13종의 전체 유효 위치가 열거·검증된다.
- [x] 잘못된 스플릿·코너·선택 수·베팅 단위가 거부된다.
- [x] 모든 지원 베팅의 RTP는 `36/37`, 하우스 엣지는 `1/37`이다.
- [x] 37개 결과 전수 정산 시 각 1단위 베팅의 순변화 합계가 `-1`이다.
- [x] 원장은 정수·합계 0·멱등 거래이며 플레이어 음수 잔액을 거부한다.
- [x] 라운드는 서버 권위 상태 전이만 허용한다.
- [x] RNG 계약은 편향·시드 노출·중복 추첨을 차단한다.
- [x] 현금 환전·실물 보상·운영 수익화·제작 일정이 제외되어 있다.
- [x] 전체 회귀 테스트 41개가 통과한다.

## 후속 승인

아래 체크박스는 **인간 검토자의 서명**을 뜻한다. 서명은 수행되지 않았으므로 전부 미체크로
유지한다. 역할별 증거 기반 결론은 `docs/approvals/R1-evidence-closure.md`에 별도로 기록했고,
그 문서는 승인 기록이 아니다. `scripts/validate_baseline.py::validate_r2_rng`가 이 섹션에 체크된
항목이 생기면 기준선을 실패시킨다.

- [ ] Design Lead: 지원 베팅·규칙 범위 승인 — 증거 기록됨, 서명 없음
- [ ] Engineering Lead: 원장·라운드·RNG 인터페이스 승인 — 증거 기록됨, 서명 없음
- [ ] Platform Integrator: 보안·감사·공급자 경계 승인 — 증거 기록됨, 서명 없음
- [ ] QA Lead: 수학·부정 테스트 독립 승인 — 증거 기록됨, 서명 없음
- [ ] Game Director / 사용자: R2 릴리스 게이트 진입 승인 — 미발행

## 사용자 승인 현황

- `USER`는 2026-09-01 세션에서 `R2-RNG-0001` 작업의 착수와 수행을 명시적으로 승인했다.
- 이 승인은 작업 수행 권한이며 R2 릴리스 게이트 진입 승인이나 최종 QA 판정이 아니다.
- 최종 게이트 권한은 `operations/collaboration.yaml`의 `final_gate: [A-50, USER]`에 그대로 남아 있다.

## R2 이월 위험 현황

- 생산용 CSPRNG 구현과 독립 통계 검증: `CLOSED_PENDING_REVIEW` (`R2-RNG-0001`)
- 데이터베이스 격리 수준과 동시성·장애 복구: `OPEN`
- 실제 네트워크 재접속, 부하, 보안 침투 시험: `OPEN`

## 결과

- Decision: `PENDING`
- Candidate: `R1 roulette + Claude-only programming / repository 1.3.0`
- Evidence closure: `docs/approvals/R1-evidence-closure.md`
- Production schedule: `PROHIBITED_BEFORE_R5`
