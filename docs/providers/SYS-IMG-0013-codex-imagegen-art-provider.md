# SYS-IMG-0013 Codex 내장 ImageGen 아트 전용 공급자 운영 가이드

상태: `REGISTERED_ENABLED / IMAGE_CAPABILITY_ONLY`
작업: `tasks/SYS-IMG-0013.json` · 소유 에이전트: `A-02` · 위험도: `MEDIUM`
게이트: `scripts/validate_baseline.py::validate_image_provider` · 시험: `tests/test_image_provider.py`

## 1. 이 공급자가 하는 일과 하지 않는 일

`codex_imagegen`은 Codex 내장 ImageGen을 이미지 능력 하나로만 사용하는 관리형 커넥터다.
기존 항목을 재사용하지 않고 고유 `provider_id`로 등록했으며 `capabilities`는 `[image]`만 갖는다.

| 항목 | 값 | 근거 |
| --- | --- | --- |
| `provider_id` | `codex_imagegen` | `providers/registry.yaml` |
| `status` | `ENABLED` | 연결 증거가 PASS·ENABLE 권고 |
| `capabilities` | `[image]` | AC-001 |
| 금지 능력 | `code`, `reasoning`, `evaluation`, `orchestration` | AC-002, ADR-0003 |
| 정보등급 | `PUBLIC`, `INTERNAL` | AC-006, 작업 가정 4 |
| 자격 증명 | `secret-ref://providers/codex-imagegen` | AC-006 |
| 활성화 증거 | `providers/evidence/SYS-IMG-0013-codex-imagegen-connection-proof.yaml` | AC-005 |

이 등록은 ADR-0003의 Claude 단독 프로그래밍 경계를 바꾸지 않는다. `codex_primary`는 `DISABLED`와
`user_selected_claude_only_programming` 사유를 그대로 유지하며 이 작업은 Codex 코드 경로 활성화
근거로 쓰일 수 없다. `code`·`reasoning`·`evaluation` 라우트는 `preferred: claude_agent`,
`fallbacks: []` 그대로다.

## 2. 라우팅

```yaml
routes:
  image: {preferred: codex_imagegen, fallbacks: []}
```

`fallbacks`는 비어 있다. 공급자가 응답하지 않으면 다른 이미지 모델로 우회하지 않고 요청을 차단한다.
전환 조건은 하나뿐이다. `providers/connection-proof.schema.json`에 유효하고 차단 프로브가 모두
`PASS`이며 `overall_result: PASS`, `activation_recommendation: ENABLE`인 관리형 연결 증거가 존재할
것. 증거가 없거나 `INCOMPLETE`이면 공급자는 `DISABLED_UNTIL_CONFIGURED`로 남고 라우트는 전환되지
않는다. 이 두 방향은 `validate_image_provider`가 매 실행마다 검사한다.

## 3. 자격 증명

별도 API 키를 발급하지 않는다. 호출은 관리형 작업 공간 인증으로 성립하며 저장소에는 참조만 남는다.

- `credential_ref: secret-ref://providers/codex-imagegen`
- `credential_source: PROVIDER_NATIVE_AUTH_STORE`
- `managed_credential_storage: managed_workspace_auth`

`providers/connection-proof.schema.json`의 `credential_source` 열거에는 관리형 앱 전용 값이 없다.
스키마가 허용하는 값 중 관리형 네이티브 인증에 해당하는 `PROVIDER_NATIVE_AUTH_STORE`로 기록하고,
실제 저장 위치는 레지스트리의 `managed_credential_storage`에
`operations/collaboration.yaml#credentials.allowed_storage`가 이미 허용하는 `managed_workspace_auth`
로 남긴다. 비밀값 자체는 저장소·프롬프트·로그·커밋·증거 어디에도 기록하지 않는다.

## 4. 연결 프로브 기록 (2026-09-02)

두 이미지는 Codex 관리형 콘솔에서 실제로 성공한 생성 호출의 산출물이다. 저장소에는 이미지 파일이
아니라 지문만 남는다.

### Probe A

- 픽셀: 1536x1024, 형식: PNG, 크기: 2,188,345 바이트
- SHA-256: `b130c05b29a29513dfefb3648c1935fa68f86822c17679c515b64ce45d5ad689`
- 상태: `CONNECTIVITY_PROBE_ONLY`

### Probe B

- 픽셀: 1254x1254, 형식: PNG, 크기: 2,739,931 바이트
- SHA-256: `920861ca200bb0ed8b273bb78a8acfd235e42cf392ac3c24eadcebc32bad0e62`
- 상태: `CONNECTIVITY_PROBE_ONLY`

두 산출물은 등록 이전에 생성되었으므로 연결 확인용 프로브 또는 후보 자산으로만 취급한다. Artifact
Contract의 정식 산출물, 프로덕션 승인 증거, 릴리스 자산으로 승격하지 않는다. 승격 시도는
`validate_image_provider`가 거부한다. 두 지문이 어떤 Artifact Contract의 `content_hash`로도 나타나면
기준선 검증이 실패한다. 후보 자산의 보관 위치와 폐기 기준은 A-30과 후속 작업에서 결정한다.

### Managed model disclosure

관리형 내장 경로는 모델 이름·버전과 호출별 과금 사용량을 호출자에게 노출하지 않았다.

- 연결 증거의 `environment.model`: `null`
- 과금 사용량: `unavailable`

확인 불가한 값은 `null` 또는 `unavailable`로만 기록한다. 모델명·버전·금액을 추정하거나 지어내지
않는다. 장기 기록 방식은 후속 작업에서 확정한다.

## 5. 호출 절차

사전 절차 (`providers/routing-policy.yaml#preflight`, `policies/cost.yaml`):

1. 요청 스키마 검증과 요청 에이전트·능력 인가.
2. 정보등급 확인. `PUBLIC`·`INTERNAL`만 허용하고 `CONFIDENTIAL`·`RESTRICTED`는 전송하지 않는다.
3. 예산 예약. `reservation_required_before_provider_call: true`이며 `stop_on_limit`를 준수해 하드
   한도(`hard_stop_ratio: 1.00`)에서 중단한다. 자동 예산 연장은 금지이고 초과 승인은 USER 권한이다.
4. 프롬프트에서 비밀값과 금지 자료 제거.

사후 절차:

1. 출력 계약 검증과 출처·공급자 약관 부착.
2. 실제 사용량 기록(`actual_usage_record_required: true`). 관리형 경로가 과금 사용량을 노출하지
   않는 동안에는 호출 건수와 산출물 지문을 기록하고 금액은 `unavailable`로 남긴다.
3. 감사 이벤트 기록. `audit/audit-event.schema.json`에 유효해야 하고 `contains_secret`은 항상
   `false`다. `request_hash`는 `sha256:` 뒤에 `{action, actor_id, resource_refs, task_id, timestamp}`
   를 `json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(",", ":"))`로 직렬화한
   UTF-8 바이트의 SHA-256을 붙여 만든다. `event_hash`는 `studio_core.rng.compute_event_hash`와
   같은 규칙으로 자기 자신을 제외한 이벤트 본문에서 계산하고 앞 이벤트의 해시로 연결한다.
4. 독립 검토로 회부. 생성자는 최종 QA 게이트를 판정하지 않는다.

## 6. 산출 이미지의 출처와 권리

정식 아트 산출물을 등록할 때 Artifact Contract의 `rights` 네 필드를 모두 채워야 한다.

- `license`: 공급자 약관에서 확인한 라이선스 문자열.
- `commercial_use`: 상용 사용 가부.
- `training_permission`: `ALLOWED` / `NOT_ALLOWED` / `NOT_APPLICABLE` / `UNKNOWN`.
- `provenance_complete`: 프롬프트·공급자·호출 시각·감사 이벤트가 모두 연결되었을 때만 `true`.

`RIGHTS_UNVERIFIED`는 `policies/cost.yaml#retry.no_retry_on`에 있으므로 권리가 확인되지 않은 호출은
재시도하지 않는다. 이번 작업의 Artifact Contract는 레지스트리 등록 문서를 대상으로 하며 프로브
이미지를 산출물로 포함하지 않는다.

## 7. Layer AI는 확정하지 않은 후속 결정

사용자 승인 문장은 "사용량이 많아지면 레이어ai도 연결하자"였다. 이는 지금 연결하라는 지시가 아니라
사용량이 늘어난 시점에 다시 판단하자는 합의다. 따라서 이 작업은 아무 임계값도 만들지 않는다.

- `layer_ai_status: DISABLED_UNTIL_CONFIGURED`
- `layer_ai_in_any_route: false`
- `layer_ai_usage_threshold: UNSET`
- `layer_ai_switch_criteria: UNSET`
- `layer_ai_switch_date: UNSET`
- `layer_ai_decision_owner: USER + A-00`

`layer_ai`는 `image` 라우트의 `fallbacks`에 등록되지 않으며 별도 작업으로 연결이 구성되기 전까지 어떤
라우트에도 나타나지 않는다. 숫자 임계값·전환 기준·일정을 이 문서나 정책 파일에 적는 것은 승인되지
않은 결정이며 `validate_image_provider`가 거부한다. R5 이전이므로 상용 제작 일정과 출시일도
확정하지 않는다.

## 8. 롤백

1. `providers/registry.yaml`에서 `codex_imagegen` 항목을 제거한다.
2. `providers/routing-policy.yaml`의 `image` 라우트를 직전 커밋 상태
   (`{preferred: layer_ai, fallbacks: []}`)로 되돌린다.
3. 신규 파일을 삭제한다. `providers/evidence/SYS-IMG-0013-codex-imagegen-connection-proof.yaml`,
   `docs/providers/SYS-IMG-0013-codex-imagegen-art-provider.md`, `tests/test_image_provider.py`,
   `audit/events/SYS-IMG-0013-events.json`, `artifacts/SYS-IMG-0013-artifact.json`,
   `handoffs/SYS-IMG-0013-handoff.json`.
4. `scripts/validate_baseline.py`에서 `validate_image_provider`와 필수 파일 목록 추가분을 직전 커밋
   상태로 되돌리고, `tasks/SYS-IMG-0013.json`의 `providers/registry.yaml`·
   `providers/routing-policy.yaml` 입력 해시를 직전 값으로 되돌린다.
5. `claude_agent`, `codex_primary`, `layer_ai` 항목과 `code`·`reasoning`·`evaluation` 라우트는 애초에
   수정 대상이 아니므로 복원할 것이 없다.
6. `python scripts/validate_baseline.py`와 `python -m unittest discover -s tests -v`를 재실행한다.

커밋과 푸시를 하지 않으므로 작업 트리 복원만으로 완전 복구된다. 파괴적 Git·파일시스템 명령은 어느
단계에서도 사용하지 않는다.
