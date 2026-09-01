# SYS-004 채팅방·권한·상태 워크플로

상태: `IMPLEMENTED / AUTOMATED_CHECKS_REQUIRED`

## 운영 원칙

- 9개 부서 허브와 업무별 하위 채팅방을 사용한다.
- 기본 가시성은 부서 전용이며, 부서 간 접근은 Handoff 또는 명시적 권한으로만 허용한다.
- 권한은 기본 거부 방식이고 모든 상시 에이전트의 운영 환경 직접 접근은 금지한다.
- 작업은 `DRAFT → READY → IN_PROGRESS → REVIEW → QA → DONE`을 기본 경로로 사용한다.
- 우회 완료는 허용하지 않으며 `DONE`은 QA Lead가 증거와 위험등급별 승인을 확인한 뒤 전환한다.
- 예산·법무·출시·R0 최종 승인은 사람만 수행한다.

기계 판독 원본은 `operations/rooms.yaml`, `operations/workflow.yaml`,
`operations/permissions.yaml`이며 판정 코드는 `studio_core/workflow.py`이다.
