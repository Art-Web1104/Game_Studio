# SYS-CLD-0011 Codex 발주 · Claude 구현 · Codex 독립검증 협업 가이드

- 상태: `ACTIVE`
- 실행 정책 원본: `operations/collaboration.yaml`
- 참조 결정: `docs/decisions/ADR-0003-claude-only-programming.md`
- 검증기: `scripts/validate_baseline.py`의 `validate_collaboration`

이 문서는 사람이 읽는 설명이고, 강제되는 규칙은 `operations/collaboration.yaml`과 검증기에 있습니다.
문서와 정책이 다르면 정책과 검증기가 우선합니다.

## 역할과 콘솔

| 역할 | 콘솔 | 대리 에이전트 | 코드 생성 | 최종 게이트 |
| --- | --- | --- | --- | --- |
| `issuer` | Codex | A-00, A-01, A-02 | 금지 | 금지 |
| `implementer` | Claude Code | A-02, A-20 | 허용(단독) | 금지 |
| `independent_verifier` | Codex | A-20, A-50 | 금지 | 금지 |
| 최종 게이트 | 사람 | A-50 | 금지 | A-50 또는 USER |

구현 콘솔과 독립 검증 콘솔은 서로 달라야 하며 검증기가 이를 강제합니다.

## 반복 절차

1. **ISSUE (Codex)** — `tasks/<TASK-ID>.json`에 `status: READY`인 Task Contract를 작성합니다.
   파일명은 `task_id`와 같아야 합니다. 소유자 1명, `budget.stop_on_limit: true`,
   승인자에 `USER` 포함, `security.data_classification`은 `INTERNAL` 이하가 필요합니다.
2. **IMPLEMENT (Claude)** — `evaluate_delegation`이 통과할 때만 착수합니다.
   `READY` 또는 `IN_PROGRESS`가 아니면 거부됩니다.
3. **SELF_VERIFY (Claude)** — 두 표준 명령을 직접 실행합니다.

   ```bash
   python scripts/validate_baseline.py
   python -m unittest discover -s tests -v
   ```

4. **SUBMIT (Claude)** — 결과를 두 파일로 제출합니다.
   - `artifacts/<TASK-ID>-artifact.json` (Artifact Contract)
   - `handoffs/<TASK-ID>-handoff.json` (Handoff Packet)
   Handoff의 `verification_evidence`에는 위 두 명령이 `check` 문자열 그대로,
   `result: PASS`로 들어가야 합니다.
5. **INDEPENDENT_VERIFY (Codex)** — 수신자는 생성자와 다른 에이전트여야 합니다.
   Codex는 두 명령을 재실행하고 계약·차이·증거를 검토한 뒤 판정을 냅니다.
6. **FINAL_GATE (사람)** — `A-50` 또는 `USER`만 최종 QA 게이트를 판정합니다.

## 게이트 함수

`studio_core/collaboration.py`는 정책을 실행 가능한 결정으로 옮깁니다. 모든 함수는 예외를 던지지 않고
`allowed`, `code`, `message`를 담은 결정 객체를 돌려주므로 거부 사유가 그대로 감사 기록이 됩니다.

| 함수 | 질문 | 대표 거부 코드 |
| --- | --- | --- |
| `evaluate_delegation(task, console=, actor_agent_id=)` | 이 Task Contract를 착수해도 되는가 | `STATUS_DENIED`, `CONSOLE_DENIED`, `ACTOR_DENIED`, `CLASSIFICATION_DENIED`, `PII_DENIED`, `SECRETS_POLICY_DENIED`, `BUDGET_POLICY_DENIED`, `APPROVER_MISSING` |
| `evaluate_role_action(role, action)` | 이 역할이 이 행위를 해도 되는가 | `ROLE_UNKNOWN`, `ACTION_DENIED` |
| `evaluate_independent_verification(handoff, console=, verifier_agent_id=)` | 이 검증자가 독립 검증을 해도 되는가 | `CONSOLE_DENIED`, `SELF_VERIFICATION_DENIED`, `MISSING_EVIDENCE` |
| `evaluate_final_gate(handoff, approver=, verification_result=)` | 이 승인자가 최종 게이트를 낼 수 있는가 | `SELF_APPROVAL_DENIED`, `GATE_DENIED`, `VERIFICATION_INCOMPLETE` |
| `evaluate_provider_activation(provider_id, target_status, proof)` | 이 Provider를 활성화해도 되는가 | `PROVIDER_DENIED`, `PROOF_MISSING`, `PROBE_INCOMPLETE`, `AUTHORIZATION_MISSING`, `CREDENTIAL_NOT_REFERENCED`, `CREDENTIAL_SOURCE_DENIED`, `SECRET_LEAK_RISK`, `PROOF_INCOMPLETE` |

행위는 기본 거부입니다. 역할 정의에 `denied`가 있으면 언제나 거부되고, `allowed`이거나 `duties`에
선언된 경우에만 허용됩니다.

`expected_paths(task_id)`는 정책의 `directories`에서 산출물 경로를, `required_commands()`는
`completion_gate.required_checks`에서 두 표준 명령을 계산하므로 경로와 명령이 문서와 코드에서
갈라지지 않습니다.

## 생성자·검증자 분리

- Artifact의 `source.created_by`는 `reviewers`에 들어갈 수 없습니다.
- Handoff의 `from_agent_id`와 `to_agent_id`는 같을 수 없습니다.
- 구현 역할은 독립 검증과 최종 QA 승인을 수행할 수 없습니다.
- 연결 증거의 `recorded_by`와 `verified_by`는 서로 달라야 합니다.

## 자격 증명 취급

- 자격 증명 값은 저장소·프롬프트·로그·커밋·증거 파일 어디에도 기록하지 않습니다.
- 저장소에는 `secret-ref://` 참조만 남기고 실제 값은 **OS 자격 증명 저장소**
  (Windows 자격 증명 관리자 등) 또는 Claude Code의 자체 인증 저장소에만 둡니다.
  이는 `policies/security.yaml`의 `secrets.storage: external_secret_broker`를
  로컬 워크스테이션에서 구현한 형태입니다.
- 검증기는 협업 산출물 전체를 평문 자격 증명 패턴으로 훑고, 발견 시 값을 출력하지 않고
  실패시킵니다(`scan_for_plaintext_secrets`). 패턴은 `studio_core/collaboration.py`에 두는데,
  검사 대상 파일에 패턴을 두면 패턴 자신이 검사에 걸리지 않도록 쓰는 부담이 생기기 때문입니다.
- `.claude/settings.json`은 `.env`와 `secrets/`, 키 파일에 대해 `Read(...)`와 `Edit(...)` deny 규칙을
  둡니다. `Edit` 규칙은 `Write`와 `NotebookEdit`에도 적용되므로 별도의 `Write(...)` 규칙 없이
  읽기·쓰기 양방향이 차단됩니다. `validate_claude_workspace`가 이 규칙 존재를 강제합니다.
- 내부 리뷰용 작업 트리(`.claude/worktrees/`)는 저장소 사본이므로 `.gitignore`로 커밋을 차단합니다.

## Provider 활성화 게이트

`claude_agent`는 증거 없이는 활성화할 수 없습니다.

1. `providers/evidence/`에 `providers/connection-proof.schema.json`을 만족하는 연결 증거를 둡니다.
2. 모든 프로브가 `PASS`이고 `overall_result: PASS`, 사용자 승인 `granted: true`,
   `credential_source`가 승인된 저장소, `secret_values_recorded: false`여야 합니다.
3. 그때만 `providers/registry.yaml`의 `claude_agent`를 `ENABLED`로 올릴 수 있습니다.
4. 증거가 없거나 불완전하면 상태는 `DISABLED_UNTIL_CONFIGURED`로 남고,
   `code`·`reasoning`·`evaluation` 요청은 `PROVIDER_UNAVAILABLE`로 차단됩니다.
5. Codex는 어떤 경우에도 코드 생성 Provider로 활성화되지 않습니다. Claude가 불가하면
   다른 모델로 우회하지 않고 `BLOCKED` 처리합니다.

## ADR-0003 경계

ADR-0003은 Codex를 코드 생성·수정·리뷰의 **대체 경로**로 쓰지 않도록 정합니다.
여기서 Codex는 대체 경로가 아니라 ADR-0003 5항의 독립 승인 경로를 수행하는 발주·검증 콘솔입니다.
Codex는 코드를 생성하지 않고, Claude 부재 시 대체 공급자가 되지도 않습니다.
이 경계를 넓히려면 A-00과 USER가 ADR을 개정해야 합니다.

## 실패 처리

- 위임 게이트 거부: 사유 코드를 그대로 Codex에 회신하고 Task Contract를 고쳐 재발주합니다.
- 명령 실패: 실패 로그를 증거로 남기고 `readiness: REWORK_REQUIRED`로 반환합니다.
- 롤백: 커밋하지 않으므로 신규 파일 삭제와 변경 파일 복원으로 완전 복구됩니다.
