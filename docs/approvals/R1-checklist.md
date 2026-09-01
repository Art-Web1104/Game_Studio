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

- [ ] Design Lead: 지원 베팅·규칙 범위 승인
- [ ] Engineering Lead: 원장·라운드·RNG 인터페이스 승인
- [ ] Platform Integrator: 보안·감사·공급자 경계 승인
- [ ] QA Lead: 수학·부정 테스트 독립 승인
- [ ] Game Director / 사용자: R2 진입 승인

## 결과

- Decision: `PENDING`
- Candidate: `R1 roulette + Claude-only programming / repository 1.3.0`
- Production schedule: `PROHIBITED_BEFORE_R5`
