# Claude Code 프로그래밍 작업장 설정

상태: `PROJECT_CONFIGURATION_READY / CLAUDE_CONNECTION_REQUIRED`

## 준비된 구성

- 루트 `CLAUDE.md`: 공통 개발 계약과 완료 조건
- `.claude/settings.json`: 프로젝트 권한과 파괴적 작업 차단
- `.claude/agents/client-engineer.md`: 클라이언트 담당
- `.claude/agents/game-server-engineer.md`: 규칙·원장·RNG 담당
- `.claude/agents/backend-platform-engineer.md`: API·저장소·CI 담당
- `.claude/agents/code-reviewer.md`: 읽기 전용 독립 코드 리뷰

## 사용 순서

1. Claude Code에서 이 저장소 루트를 작업 폴더로 연다.
2. `/context`로 `CLAUDE.md`가 로드됐는지 확인한다.
3. `/permissions`에서 프로젝트 규칙이 적용됐는지 확인한다.
4. `python scripts/validate_baseline.py`를 실행한다.
5. `python -m unittest discover -s tests -v`를 실행한다.
6. 실제 연결 검증이 끝나면 `providers/registry.yaml`의 `claude_agent`를 `ENABLED`로 승격한다.

## 연결 전 동작

Claude가 연결되지 않은 동안 `code`, `reasoning`, `evaluation` 요청은 실패해야 한다. Codex나
다른 코드 모델로 자동 우회하지 않는다. API 키·토큰은 저장소, CLAUDE.md, 설정, 로그에 넣지
않으며 Claude의 공식 인증 저장소 또는 실행 환경의 비밀 저장소에서만 관리한다.
