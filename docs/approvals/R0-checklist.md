# R0 승인 체크리스트

현재 상태: `R0_APPROVED`

## 자동 검증

- [x] Constitution 파일과 버전이 존재한다.
- [x] Registry에 상시 에이전트가 정확히 9종 등록되어 있다.
- [x] Registry와 개별 Agent Definition의 ID·경로·역할이 일치한다.
- [x] 모든 에이전트에 최소 권한, 금지사항, 승인, 에스컬레이션 규칙이 있다.
- [x] Task, Handoff, Artifact 스키마가 유효하다.
- [x] 세 예제가 각 스키마를 통과한다.
- [x] 예제 간 task, agent, artifact 참조가 일치한다.
- [x] R5 전 제작 일정 금지 정책이 기계 판독 가능한 형태로 존재한다.
- [x] 전체 단위 테스트가 통과한다.
- [x] 9개 부서 채팅 허브와 하위 채팅방, 최소 권한, 상태 전이가 정의되어 있다.
- [x] 승인된 지식만 검색되고 대화·외부 출력은 자동 승격되지 않는다.
- [x] 외부 AI 공급자 요청·응답·라우팅·실패 계약이 정의되어 있다.
- [x] 상시 에이전트 9종 모두 Eval Set v1과 독립 검토자가 연결되어 있다.
- [x] 룰렛 규칙·지급·0 처리·결정론·원장 QA 명세와 고정 벡터가 있다.
- [x] 보안·비용·감사·위험 정책이 기계 검증을 통과한다.

## 사람 승인

- [x] 사용자 / 사업 책임자: 범위와 권한 구조 최종 승인
- [x] Game Director: 운영 가능성 검증 권고 `PASS`
- [x] Platform Integrator: 스키마·권한·검증 가능성 권고 `PASS`
- [x] QA Lead: 독립 검증과 차단 권한 권고 `PASS`

## 승인 결과

- Decision: `APPROVED`
- Approved version: `1.1.0`
- Approved at: `2026-08-31T00:43:56Z`
- Final approver: `USER`
- Approval record: `approvals/SYS-010-R0-approval.yaml`
- Automated validation: `PASS (2026-08-28)`
- Evidence: 기준선 `1.1.0`의 `python scripts/validate_baseline.py` 및 `python -m unittest discover -s tests -v`
