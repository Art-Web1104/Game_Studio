# AI Game Studio — R0 Approved / R1 Claude Programming Candidate

이 저장소는 TS STUDIO의 AI 게임 개발 시스템을 위한 실행 가능한 R0 기준선입니다.
현재 범위는 게임 제작 일정 수립 전 필요한 제어 시스템 기준선의 확정입니다.

- `SYS-001`: Studio Constitution v1
- `SYS-002`: 상시 에이전트 9종과 Agent Registry
- `SYS-003`: Task, Handoff, Artifact 계약 스키마
- `SYS-004`: 채팅방, 권한, 작업 상태 워크플로
- `SYS-005`: 지식 승인, 검색, 폐기 정책
- `SYS-006`: Claude Code 중심 Provider Adapter 계약
- `SYS-007`: 상시 에이전트 9종 Eval Set v1
- `SYS-008`: 유럽식 단일 제로 룰렛 규칙·QA 기준선
- `SYS-009`: 보안, 비용, 감사, 위험 정책

## 현재 상태

- 저장소 버전: `1.3.0`
- R0 기준선: `1.1.0 approved`
- R1 룰렛: `candidate`
- 프로그래밍 공급자: `Claude Code only / connection required`
- 제품 범위: 환전·현금 인출이 없는 소셜 카드·카지노 게임
- 제작 일정: `R5` 승인 전 수립 금지
- 완료 범위: `SYS-001`부터 `SYS-010`까지 구현·승인됨
- 현재 단계: `R1` 룰렛 규칙·정수 원장·RNG 인터페이스 자동 검증
- 다음 게이트: `R1` 사람 승인 후 `R2` 기술 위험 제거

## 저장소 구조

```text
ai-game-studio/
├── AGENTS.md
├── docs/
│   ├── constitution/studio-constitution-v1.md
│   ├── decisions/ADR-0001-r0-baseline.md
│   └── approvals/R0-checklist.md
├── agents/
│   ├── agent.schema.json
│   ├── registry.yaml
│   └── <department>/<agent>.yaml
├── contracts/
│   ├── task.schema.json
│   ├── handoff.schema.json
│   └── artifact.schema.json
├── examples/
│   ├── task.example.json
│   ├── handoff.example.json
│   └── artifact.example.json
├── operations/          # 채팅방, 권한, 작업 상태
├── knowledge/           # 승인 지식 계약과 검색 정책
├── providers/           # 외부 AI 중립 어댑터 계약
├── evals/               # 상시 에이전트 9종 평가 데이터셋
├── games/roulette/      # 첫 수직 검증 규칙과 QA 벡터
├── policies/            # 보안, 비용, 감사, 위험
├── audit/               # 감사 이벤트 계약
├── studio_core/         # 정책 판정 참조 코드
├── scripts/validate_baseline.py
└── tests/test_baseline.py
```

## 검증

Python 3.11 이상과 PyYAML 6 이상이 필요합니다.

```bash
python scripts/validate_baseline.py
python -m unittest discover -s tests -v
```

검증기는 다음을 확인합니다.

1. Constitution과 필수 기준선 파일의 존재
2. Registry에 정확히 9개의 상시 에이전트가 있는지
3. 모든 에이전트의 ID·경로·권한·승인·금지사항과 Eval Set이 일치하는지
4. 세 계약 스키마의 구조와 예제 유효성
5. 예제 간 작업·에이전트·산출물 참조 무결성
6. 채팅방·작업 상태·지식·외부 AI 라우팅 정책
7. 룰렛 지급 벡터, 0 처리, QA 게이트
8. 보안·비용·감사·위험 정책과 `R5` 이전 제작 일정 금지

## 운영 시작점

모든 사람과 에이전트는 작업 전에 [AGENTS.md](AGENTS.md)와
[Studio Constitution](docs/constitution/studio-constitution-v1.md)을 읽어야 합니다.
상위 정책과 충돌하는 요청은 실행하지 않고 `Game Director`에게 에스컬레이션합니다.
