"""R2-QA-0006 종결 후보 증거 패킷의 교차 검증 스위트.

이 모듈은 다섯 R2 유닛(`R2-RNG-0001`, `R2-DBC-0002`, `R2-NET-0003`, `R2-LOAD-0004`,
`R2-SEC-0005`)이 남긴 계약·아티팩트·핸드오프·보고서·감사 기록과, 이 유닛이 새로 만든 종결
후보 산출물을 함께 검사한다. 성격은 **가산적 증거 검증기**다. 기존 시험을 다시 쓰지 않고,
기존 단언을 완화하지 않으며, 기존 파일을 하나도 건드리지 않는다.

무엇을 검사하는가

* 다섯 유닛 삼중 계약 15개 문서의 스키마 유효성, 식별자 정렬, 생성자·검토자 분리,
  발신자·수신자 분리, 완료 게이트가 요구하는 두 표준 명령의 `PASS` 기록.
* 각 아티팩트가 **자기 방식으로 선언한** 해시 키의 실제 파일 대조. 다섯 유닛의 키 이름은
  통일되어 있지 않다(`component_hash_*`, `contract_hash`, `test_suite_hash`, ...). 하나의
  이름 규칙을 가정하고 검사하면 규칙에서 벗어난 키가 조용히 검사되지 않은 채 남는다.
  그래서 유닛별 실제 키 이름을 명시적으로 묶고, 선언된 `sha256:` 값 키 집합이 그 묶음으로
  **빠짐없이** 덮이는지를 함께 단언한다.
* 이 계약이 고정한 54개 입력 경로 전부의 정규 LF 해시.
* 다섯 유닛 감사 기록과 이 유닛 감사 기록의 스키마 유효성 및 해시 연쇄.
* 종결 보고서·상태 문서·감사 기록·아티팩트·핸드오프의 상호 일관성.
* `A-50`이 공급한 다섯 PR의 호스티드 CI 증거가 문자 단위로 그대로 옮겨졌는지.
* `codex` 콘솔이 `independent_verifier` 역할로 `A-50`을 대행해 발행한 독립 검증 판정
  (`PASS`)과 종결 후보 권고(`ISSUED`)가 아티팩트·핸드오프·감사 기록·보고서·상태 문서에
  같은 값으로 전사되었는지, 그리고 그 판정의 발행 주체가 `A-20`이 아니라고 기록되었는지.
* 판정 경계: 독립 검증은 `PASS`지만 `A-50` 최종 QA 게이트와 `A-02`·`A-00`·`USER` 최종 QA는
  `NOT_RUN`, 종결 상태 값은 `CLOSED_PENDING_DIRECTOR_AND_USER`이며
  `DONE`·`CLOSED`·`PRODUCTION_READY`가 아니라는 것.
* 실패가 주입되면 종결 권고가 산출되지 않고 `REWORK_REQUIRED`가 강제된다는 실행 가능한 경로.

무엇을 검사하지 않는가

이 모듈은 어떤 QA 판정도 발행하지 않는다. 여기서 모든 단언이 통과한다는 사실은 증거가
정합적이라는 뜻이지 유닛이 승인되었다는 뜻이 아니다. 최종 게이트는 `A-50`과 `USER`에 있다.
독립 검증 판정 역시 이 모듈이 만들지 않는다. 이 모듈이 하는 일은 공급된 판정이 산출물에
같은 값으로 남았는지, 그리고 그 판정이 구현자의 것으로 둔갑하지 않았는지 보는 것뿐이다.

결정론

표준 라이브러리와 이미 선언된 저장소 모듈만 사용한다. 네트워크, 하위 프로세스, 난수, 고정
대기, 임시 작업 공간을 쓰지 않는다. `DeterminismTests`가 이 모듈의 AST를 직접 읽어 그 사실을
검사하므로, 나중에 누가 그 성질을 깨면 여기서 실패한다.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import re
import sys
import unittest
from dataclasses import dataclass
from typing import Any, Mapping

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts.validate_baseline import (  # noqa: E402
    BaselineValidationError,
    load_yaml,
    validate_instance,
)
from studio_core.collaboration import (  # noqa: E402
    evaluate_delegation,
    evaluate_independent_verification,
    evaluate_role_action,
    missing_evidence_commands,
    required_commands,
    scan_for_plaintext_secrets,
)
from studio_core.integrity import hash_file, verify_file  # noqa: E402
from studio_core.rng import verify_audit_chain  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]

UNIT_ID = "R2-QA-0006"

#: 이 유닛이 교차 검증하는 다섯 R2 유닛.
SOURCE_UNITS: tuple[str, ...] = (
    "R2-RNG-0001",
    "R2-DBC-0002",
    "R2-NET-0003",
    "R2-LOAD-0004",
    "R2-SEC-0005",
)

TASK_PATH = f"tasks/{UNIT_ID}.json"
ARTIFACT_PATH = f"artifacts/{UNIT_ID}-artifact.json"
HANDOFF_PATH = f"handoffs/{UNIT_ID}-handoff.json"
REPORT_PATH = f"docs/approvals/{UNIT_ID}-closure-report.md"
STATUS_PATH = f"docs/status/{UNIT_ID}-closure-candidate.md"
EVENTS_PATH = f"audit/events/{UNIT_ID}-events.json"
SUITE_PATH = "tests/test_r2_qa_closure.py"

#: 이 유닛이 저장소에 추가한 파일 전부. 일곱 건이고 전부 신규다. 기존 파일 수정은 0건이다.
CREATED_PATHS: tuple[str, ...] = (
    TASK_PATH,
    ARTIFACT_PATH,
    HANDOFF_PATH,
    REPORT_PATH,
    STATUS_PATH,
    EVENTS_PATH,
    SUITE_PATH,
)

#: 계약 단계에서 만들어진 세 건과, 구현 단계에서 만들어진 네 건.
CONTRACT_PHASE_PATHS: tuple[str, ...] = (TASK_PATH, ARTIFACT_PATH, HANDOFF_PATH)
IMPLEMENTATION_PATHS: tuple[str, ...] = (REPORT_PATH, STATUS_PATH, EVENTS_PATH, SUITE_PATH)

SCHEMA_BY_KIND = {
    "task": "contracts/task.schema.json",
    "artifact": "contracts/artifact.schema.json",
    "handoff": "contracts/handoff.schema.json",
}
AUDIT_EVENT_SCHEMA_PATH = "audit/audit-event.schema.json"

# ---------------------------------------------------------------------------------------
# 유닛별 아티팩트가 실제로 쓴 해시 키 이름
# ---------------------------------------------------------------------------------------
#
# 다섯 유닛은 서로 다른 시점에, 서로 다른 이름 규칙으로 구성 요소 해시를 선언했다. 아래 표는
# 그 실제 이름을 저장소 경로에 묶는다. 표를 하나의 접두사 규칙(`component_hash_*`)으로
# 줄이면 `R2-DBC-0002`의 `sql_schema_hash`나 `R2-NET-0003`의 `validator_hash`가 검사되지
# 않은 채 남으므로, 규칙 대신 실제 이름을 적는다.
COMPONENT_HASH_BINDINGS: dict[str, dict[str, str]] = {
    "R2-RNG-0001": {
        "statistics_module_hash": "studio_core/rng_stats.py",
        "record_schema_hash": "games/roulette/rng-draw-record.schema.json",
    },
    "R2-DBC-0002": {
        "contract_hash": "games/roulette/durable-state-contract.yaml",
        "sql_schema_hash": "games/roulette/durable-state-schema.sql",
        "test_hash": "tests/test_durable_state.py",
        "test_suite_hash": "tests/test_durable_state.py",
    },
    "R2-NET-0003": {
        "contract_hash": "games/roulette/reconnect-contract.yaml",
        "test_suite_hash": "tests/test_reconnect_continuity.py",
        "validator_hash": "scripts/validate_baseline.py",
        "design_document_hash": "docs/games/R2-reconnect-continuity.md",
        "task_contract_hash": "tasks/R2-NET-0003.json",
    },
    "R2-LOAD-0004": {
        "task_contract_hash": "tasks/R2-LOAD-0004.json",
        "component_hash_load_observation_contract_yaml": (
            "games/roulette/load-observation-contract.yaml"
        ),
        "component_hash_observe_r2_load_py": "scripts/observe_r2_load.py",
        "component_hash_test_load_observation_py": "tests/test_load_observation.py",
        "component_hash_R2_load_observation_md": "docs/games/R2-load-observation.md",
        "component_hash_R2_LOAD_0004_validation_report_md": (
            "docs/approvals/R2-LOAD-0004-validation-report.md"
        ),
        "component_hash_R2_LOAD_0004_events_json": "audit/events/R2-LOAD-0004-events.json",
    },
    "R2-SEC-0005": {
        "task_contract_hash": "tasks/R2-SEC-0005.json",
        "component_hash_security_verification_contract": (
            "games/roulette/security-verification-contract.yaml"
        ),
        "component_hash_verification_harness": "scripts/verify_r2_security.py",
        "component_hash_verification_test_suite": "tests/test_security_verification.py",
        "component_hash_design_document": "docs/games/R2-security-verification.md",
        "component_hash_validation_report": "docs/approvals/R2-SEC-0005-validation-report.md",
        "component_hash_audit_events": "audit/events/R2-SEC-0005-events.json",
    },
}

#: 저장소 경로에 묶이지 **않는** 해시 키와 그 이유. `R2-RNG-0001`은 게이트 위반으로 폐기한
#: 초안의 해시를 남겼다. 그 초안은 저장소에 없고 앞으로도 없어야 하므로 파일 대조 대상이
#: 아니다. 이 사전이 있어야 "선언된 해시 키는 전부 묶였다"는 단언이 성립한다.
UNBOUND_HASH_KEYS: dict[str, dict[str, str]] = {
    "R2-RNG-0001": {
        "recovered_draft_hash": (
            "게이트 위반으로 폐기된 초안의 해시다. 저장소에 존재하지 않는 내용이므로 파일 "
            "대조 대상이 아니며, 회수 기록 docs/operations/R2-RNG-0001-recovery.md가 그 "
            "경위를 남긴다."
        ),
    },
}

#: 이 유닛의 아티팩트가 네 신규 구현 산출물에 대해 선언하는 구성 요소 해시 키.
CLOSURE_COMPONENT_HASH_BINDINGS: dict[str, str] = {
    "component_hash_closure_report": REPORT_PATH,
    "component_hash_closure_candidate_status": STATUS_PATH,
    "component_hash_closure_audit_events": EVENTS_PATH,
    "component_hash_closure_test_suite": SUITE_PATH,
}

# ---------------------------------------------------------------------------------------
# A-50이 GitHub CLI로 취득해 공급한 외부 증거 (Claude는 재조회하지 않았다)
# ---------------------------------------------------------------------------------------

HOSTED_CI_EVIDENCE_SOURCE = "GitHub CLI evidence supplied by A-50"
HOSTED_CI_REPOSITORY = "https://github.com/Art-Web1104/Game_Studio"

#: `.github/workflows/ci.yml`이 발행하는 세 체크의 이름. 공급된 증거는 세 건 모두 SUCCESS다.
HOSTED_CI_CHECK_NAMES: tuple[str, ...] = (
    "Baseline, tests and compile (Python 3.11)",
    "Baseline, tests and compile (Python 3.12)",
    "Repository secret scan",
)
HOSTED_CI_CHECK_CONCLUSION = "SUCCESS"

#: 다섯 PR 기록. 값은 공급된 그대로이며 이 시험은 산출물이 이 값과 문자 단위로 같은지만 본다.
HOSTED_CI_PR_RECORDS: tuple[dict[str, Any], ...] = (
    {
        "unit": "R2-RNG-0001",
        "number": 2,
        "url": "https://github.com/Art-Web1104/Game_Studio/pull/2",
        "merged_at": "2026-09-01T11:41:04Z",
        "merge_commit": "69b314595293444b07d5b490d2f6707a4245d9a9",
    },
    {
        "unit": "R2-DBC-0002",
        "number": 4,
        "url": "https://github.com/Art-Web1104/Game_Studio/pull/4",
        "merged_at": "2026-09-01T12:27:58Z",
        "merge_commit": "8a3f9867e67a4bb6a4e07b23af7297f4f2f735e9",
    },
    {
        "unit": "R2-NET-0003",
        "number": 11,
        "url": "https://github.com/Art-Web1104/Game_Studio/pull/11",
        "merged_at": "2026-09-02T08:58:52Z",
        "merge_commit": "13d826427ad3c55c36f861fa1fc56961dd474559",
    },
    {
        "unit": "R2-LOAD-0004",
        "number": 12,
        "url": "https://github.com/Art-Web1104/Game_Studio/pull/12",
        "merged_at": "2026-09-02T11:11:52Z",
        "merge_commit": "70bcd9d9bf96b4d0fcbe38492d0ea6ab0e95968d",
    },
    {
        "unit": "R2-SEC-0005",
        "number": 13,
        "url": "https://github.com/Art-Web1104/Game_Studio/pull/13",
        "merged_at": "2026-09-02T13:12:55Z",
        "merge_commit": "f564bce93c4099ba31f395f139c1561eb548a82b",
    },
)

#: `A-50`이 f564bce 시점의 깨끗한 작업 트리에 대해 실행해 공급한 명령 결과. 이 시험은 이 값이
#: 산출물에 그대로 옮겨졌는지만 본다. Claude가 이 실행을 재현했다고 주장하지 않는다.
A50_SUPPLIED_RUN_FACTS: dict[str, int] = {
    "a50_supplied_focused_run_tests": 405,
    "a50_supplied_baseline_stages_passed": 20,
    "a50_supplied_baseline_stages_failed": 0,
    "a50_supplied_full_suite_tests": 792,
    "a50_supplied_full_suite_skipped": 4,
    "a50_supplied_secret_scan_files": 216,
    "a50_supplied_secret_scan_findings": 0,
}
A50_SUPPLIED_BASE_COMMIT = "f564bce93c4099ba31f395f139c1561eb548a82b"

# ---------------------------------------------------------------------------------------
# codex 콘솔이 independent_verifier 역할로 A-50을 대행해 발행한 독립 검증 판정
# ---------------------------------------------------------------------------------------
#
# 이 값들은 발행된 판정을 그대로 옮긴 것이다. `A-20`은 이 판정을 만들지 않았고 재현하지도
# 않았다. 아래 단언이 확인하는 것은 "산출물이 공급된 값과 같은가"와 "발행 주체가 구현자로
# 둔갑하지 않았는가"이지, 판정 자체의 진위가 아니다.

INDEPENDENT_VERIFICATION_CONSOLE = "codex"
INDEPENDENT_VERIFICATION_ROLE = "independent_verifier"
INDEPENDENT_VERIFICATION_ACTS_FOR = "A-50"
INDEPENDENT_VERIFICATION_VERDICT = "PASS"
INDEPENDENT_VERIFICATION_DATE = "2026-09-03"
INDEPENDENT_VERIFICATION_SCOPE_FILE_COUNT = 7
INDEPENDENT_VERIFICATION_TRACKED_FILES_MODIFIED = 0
CLOSURE_CANDIDATE_RECOMMENDATION = "ISSUED"

#: 독립 검증자가 이 유닛의 신규 7건이 존재하는 상태에서 재실행해 공급한 관측값.
INDEPENDENT_SUPPLIED_RUN_FACTS: dict[str, int] = {
    "independent_verification_closure_suite_tests": 84,
    "independent_verification_focused_r2_suite_tests": 405,
    "independent_verification_baseline_stages_passed": 20,
    "independent_verification_baseline_stages_failed": 0,
    "independent_verification_full_suite_tests": 876,
    "independent_verification_full_suite_skipped": 4,
    "independent_verification_secret_scan_files": 223,
    "independent_verification_secret_scan_findings": 0,
}

#: 독립 검증 판정을 남긴 감사 이벤트의 action. 판정이 기록에서 사라지면 여기서 걸린다.
INDEPENDENT_VERDICT_EVENT_ACTION = (
    "INDEPENDENT_VERIFICATION_VERDICT_PASS_SUPPLIED_BY_CODEX_FOR_A50"
    "_CLOSURE_CANDIDATE_RECOMMENDATION_ISSUED_FINAL_GATE_STILL_NOT_RUN"
)

# ---------------------------------------------------------------------------------------
# 종결 상태와 게이트 판정
# ---------------------------------------------------------------------------------------

CLOSURE_STATUS = "CLOSED_PENDING_DIRECTOR_AND_USER"

#: Handoff의 검증 증거 행 접두사. 게이트 판정 행과, 공급받은 관측을 옮긴 행을 구분한다.
#: 세 접두사는 서로 겹치지 않아야 한다. 겹치면 판정 행과 관측 행이 섞여 읽힌다.
GATE_ROW_PREFIX = "게이트 미발행 — "
SUPPLIED_ROW_PREFIX = "A-50 공급 증거 — "
INDEPENDENT_ROW_PREFIX = "독립 검증 공급 — "

#: 이 유닛이 절대 주장해서는 안 되는 상태 값. 종결 후보는 종결이 아니다.
PROHIBITED_CLOSURE_STATUSES: tuple[str, ...] = ("DONE", "CLOSED", "PRODUCTION_READY")

#: 미발행으로 유지되어야 하는 판정 필드와 그 값. 독립 검증이 `PASS`로 끝났다는 사실은 이
#: 목록을 하나도 줄이지 않는다. `INDEPENDENT_VERIFY`는 `FINAL_GATE`가 아니기 때문이다.
PENDING_GATE_FIELDS: dict[str, str] = {
    "a50_qa_gate_decision": "NOT_RUN",
    "a02_gate_decision": "NOT_RUN",
    "a00_gate_decision": "NOT_RUN",
    "user_final_approval": "NOT_RUN",
    "hosted_ci_status_for_this_unit": "NOT_RUN",
    "commit_push_merge_status": "NOT_RUN",
}

#: `AC-007`이 축약도 삭제도 금지한 여섯 한계. 보고서와 상태 문서에 그대로 있어야 한다.
KNOWN_LIMIT_MARKERS: tuple[str, ...] = (
    "한계 1: 단일 사용자 로컬 참조 구현 범위",
    "한계 2: 운영·외부 환경 비대상",
    "한계 3: SLO·용량 약속 없음",
    "한계 4: `R5` 승인 이전 일정 확정 금지",
    "한계 5: `R2-LOAD-0004` 수정 이전 결함이 남긴 임시 작업 공간 20건",
    "한계 6: `R2-SEC-0005` 현재 실행의 임시 작업 공간 잔여 0건",
)

STALE_WORKSPACE_COUNT = 20
STALE_WORKSPACE_PREFIX = "ts-studio-r2-load-"
SEC_LEFTOVER_WORKSPACE_COUNT = 0

#: 경로 성분 하나라도 이 집합에 들어가면 아트·자산 경로로 본다. 성분 단위로 비교하는 이유는
#: `artifacts/`가 부분 문자열로 `art`를 품기 때문이다. 부분 문자열 검사는 거짓 양성을 낸다.
ART_PATH_SEGMENTS = frozenset({"art", "arts", "assets", "asset", "images", "image", "media"})
IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".psd", ".tga"})
R4_PREFIX = "R4-"

#: 이 모듈이 절대 임포트하지 않아야 하는 것들. 결정론과 무네트워크의 실행 가능한 경계다.
FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "http",
        "http.client",
        "multiprocessing",
        "random",
        "requests",
        "secrets",
        "select",
        "signal",
        "socket",
        "ssl",
        "subprocess",
        "threading",
        "time",
        "urllib",
        "urllib.request",
    }
)

#: Claude가 자기 작업에 QA 합격을 자칭했다고 읽힐 수 있는 표현. 산출물 어디에도 없어야 한다.
#: 마지막 두 항목은 독립 검증 판정을 구현자가 자기 것으로 적는 경우를 막는다. 부정문("수행하지
#: 않았다")은 걸리지 않고 긍정 종결형("수행했다")만 걸리도록 어미를 명시한다.
SELF_APPROVAL_PATTERNS: tuple[str, ...] = (
    r"QA\s*PASS\s*(?:판정|승인)?\s*(?:완료|발행)",
    r"Claude(?:가|는)[^\n]{0,40}QA[^\n]{0,20}(?:합격|승인|통과)(?:했|시켰|을 발행)",
    r"최종\s*QA\s*게이트\s*(?:통과|승인|합격)했",
    r"A-50\s*(?:유닛별\s*)?(?:독립\s*)?QA\s*PASS\s*권고\s*발행됨",
    r"(?:Claude|A-20)(?:가|이|은|는)[^\n]{0,40}독립\s*검증[^\n]{0,10}"
    r"(?:수행|발행|판정)(?:했|하였|한다|함)",
    r"(?:Claude|A-20)(?:가|이|은|는)[^\n]{0,40}최종\s*게이트[^\n]{0,10}"
    r"(?:판정|발행)(?:했|하였|한다|함)",
)

#: 절대 경로·호스트명·계정명이 산출물에 새어 들어갔는지 보는 패턴.
ABSOLUTE_PATH_PATTERNS: tuple[str, ...] = (
    r"[A-Za-z]:[\\/](?:Users|Windows|Program Files|Temp|AppData)",
    r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+",
    r"/(?:home|Users)/[A-Za-z0-9._-]+/",
    r"/(?:tmp|var/folders)/[A-Za-z0-9._-]{4,}/",
)


# ---------------------------------------------------------------------------------------
# 읽기 도우미
# ---------------------------------------------------------------------------------------


def _read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _read_json(relative: str) -> dict[str, Any]:
    value = json.loads(_read_text(relative))
    if not isinstance(value, dict):  # pragma: no cover - 계약 위반은 즉시 드러나야 한다
        raise BaselineValidationError(f"{relative}: root must be an object")
    return value


def _schema(kind: str) -> dict[str, Any]:
    return _read_json(SCHEMA_BY_KIND[kind])


def _triplet(unit: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        _read_json(f"tasks/{unit}.json"),
        _read_json(f"artifacts/{unit}-artifact.json"),
        _read_json(f"handoffs/{unit}-handoff.json"),
    )


def _repo_relative(uri: str) -> str | None:
    return uri[len("repo://") :] if uri.startswith("repo://") else None


def _declared_hash_keys(specification: Mapping[str, Any]) -> set[str]:
    """선언 값이 `sha256:` 형식인 명세 키 전부."""

    return {
        key
        for key, value in specification.items()
        if isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)
    }


def canonical_request_hash(descriptor: Mapping[str, Any]) -> str:
    """감사 이벤트의 `request_hash`를 그 요청 서술로부터 재계산한다.

    기존 유닛의 감사 기록은 불투명한 값을 남겼다. 이 유닛은 값을 파생 가능하게 만들어,
    나중에 누가 이벤트 본문을 바꾸면서 `request_hash`만 그대로 두는 일이 검사에 걸리게 한다.
    """

    payload = json.dumps(descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def request_descriptor(event: Mapping[str, Any]) -> dict[str, Any]:
    """`canonical_request_hash`가 받는 서술. 이벤트가 무엇을 대상으로 했는지만 담는다."""

    return {
        "action": event["action"],
        "resource_refs": list(event["resource_refs"]),
        "task_id": event["task_id"],
        "timestamp": event["timestamp"],
    }


def path_is_art_or_r4(relative: str) -> bool:
    """경로가 R4 산출물 또는 아트·자산·이미지 경로인지 판정한다."""

    parts = pathlib.PurePosixPath(relative).parts
    if any(part in ART_PATH_SEGMENTS for part in parts):
        return True
    if any(part.startswith(R4_PREFIX) for part in parts):
        return True
    return pathlib.PurePosixPath(relative).suffix.lower() in IMAGE_SUFFIXES


# ---------------------------------------------------------------------------------------
# AC-011: 실패가 종결 권고를 차단하는 실행 가능한 경로
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ClosureDecision:
    """종결 후보 권고 여부와 그 근거.

    `readiness`는 검증 결과만으로 정해진다. 게이트 판정(`A-50`, `A-02`, `A-00`, `USER`)은
    입력이 아니다. 게이트가 `NOT_RUN`이라는 사실이 재작업을 강제해서는 안 되고, 반대로 모든
    검증이 통과했다는 사실이 게이트를 대신해서도 안 되기 때문이다. 그래서 통과 경로에서도
    `qa_pass_recommendation`은 언제나 `NOT_RUN`이고 `final_gate_owners`는 비지 않는다.
    """

    readiness: str
    closure_candidate_recommended: bool
    closure_status: str | None
    blocked_by: tuple[str, ...]
    qa_pass_recommendation: str
    final_gate_owners: tuple[str, ...]


def evaluate_closure_readiness(results: Mapping[str, str]) -> ClosureDecision:
    """검증 결과 묶음으로부터 readiness와 종결 후보 권고 여부를 산출한다.

    `PASS`가 아닌 항목이 하나라도 있으면 종결 권고는 산출되지 않고 `REWORK_REQUIRED`가
    강제된다. 이 규칙은 문서의 문장이 아니라 여기의 분기다.
    """

    if not results:
        return ClosureDecision(
            readiness="REWORK_REQUIRED",
            closure_candidate_recommended=False,
            closure_status=None,
            blocked_by=("<no verification results supplied>",),
            qa_pass_recommendation="NOT_RUN",
            final_gate_owners=("A-50", "USER"),
        )

    blocked = tuple(sorted(name for name, result in results.items() if result != "PASS"))
    if blocked:
        return ClosureDecision(
            readiness="REWORK_REQUIRED",
            closure_candidate_recommended=False,
            closure_status=None,
            blocked_by=blocked,
            qa_pass_recommendation="NOT_RUN",
            final_gate_owners=("A-50", "USER"),
        )
    return ClosureDecision(
        readiness="READY_FOR_REVIEW",
        closure_candidate_recommended=True,
        closure_status=CLOSURE_STATUS,
        blocked_by=(),
        qa_pass_recommendation="NOT_RUN",
        final_gate_owners=("A-50", "USER"),
    )


# ---------------------------------------------------------------------------------------
# 1. 동결 입력 (AC-014, AC-008, AC-009)
# ---------------------------------------------------------------------------------------


class FrozenInputTests(unittest.TestCase):
    """계약이 고정한 54개 경로가 하나도 바뀌지 않았음을 재계산으로 확인한다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.task = _read_json(TASK_PATH)
        cls.inputs = cls.task["inputs"]

    def test_the_contract_pins_exactly_fifty_four_unique_paths(self) -> None:
        self.assertEqual(len(self.inputs), 54)
        uris = [item["uri"] for item in self.inputs]
        self.assertEqual(len(uris), len(set(uris)), "동결 입력에 중복 경로가 있다")

    def test_every_pinned_path_exists_and_matches_its_declared_canonical_hash(self) -> None:
        for item in self.inputs:
            relative = _repo_relative(item["uri"])
            with self.subTest(uri=item["uri"]):
                self.assertIsNotNone(relative, "동결 입력은 repo:// 경로여야 한다")
                assert relative is not None
                path = ROOT / relative
                self.assertTrue(path.is_file(), f"{relative} 가 없다")
                decision = verify_file(path, item["content_hash"], label=relative)
                self.assertTrue(decision.matches, decision.message)

    def test_the_pinned_set_is_grouped_as_the_artifact_declares(self) -> None:
        """아티팩트가 적은 여섯 묶음의 합이 54와 같고, 각 묶음의 실제 개수와 일치한다."""

        artifact = _read_json(ARTIFACT_PATH)["specification"]
        relatives = [_repo_relative(item["uri"]) or "" for item in self.inputs]
        actual = {
            "inputs_group_r2_triplets": sum(
                1
                for rel in relatives
                if any(rel.endswith(f"{unit}.json") or f"{unit}-" in rel for unit in SOURCE_UNITS)
                and rel.split("/")[0] in {"tasks", "artifacts", "handoffs"}
            ),
            "inputs_group_audit_events": sum(1 for rel in relatives if rel.startswith("audit/events/")),
            "inputs_group_test_modules": sum(1 for rel in relatives if rel.startswith("tests/")),
            "inputs_group_unit_contracts": sum(1 for rel in relatives if rel.startswith("games/roulette/")),
        }
        for key, count in actual.items():
            with self.subTest(group=key):
                self.assertEqual(artifact[key], count)
        declared_total = sum(
            artifact[key]
            for key in (
                "inputs_group_governance_and_schemas",
                "inputs_group_r2_triplets",
                "inputs_group_unit_contracts",
                "inputs_group_reports_and_status",
                "inputs_group_audit_events",
                "inputs_group_test_modules",
            )
        )
        self.assertEqual(declared_total, 54)
        self.assertEqual(artifact["inputs_pinned_total"], 54)

    def test_the_five_frozen_test_modules_are_byte_identical_to_the_pinned_values(self) -> None:
        """AC-002: 기존 단언이 완화되지 않았음을 시험 파일 해시로 드러낸다."""

        pinned = {
            _repo_relative(item["uri"]): item["content_hash"]
            for item in self.inputs
            if (_repo_relative(item["uri"]) or "").startswith("tests/")
        }
        expected = {
            "tests/test_rng.py",
            "tests/test_durable_state.py",
            "tests/test_reconnect_continuity.py",
            "tests/test_load_observation.py",
            "tests/test_security_verification.py",
        }
        self.assertEqual(set(pinned), expected)
        for relative, declared in pinned.items():
            with self.subTest(module=relative):
                self.assertEqual(hash_file(ROOT / relative, label=relative), declared)

    def test_no_input_or_deliverable_reaches_r4_art_assets_or_images(self) -> None:
        """AC-008: 무결성 재고정 연쇄가 아트 경로에 닿지 않는다."""

        paths = [_repo_relative(item["uri"]) or "" for item in self.inputs]
        paths += [
            _repo_relative(item["target_uri"]) or "" for item in self.task["deliverables"]
        ]
        for relative in paths:
            with self.subTest(path=relative):
                self.assertFalse(path_is_art_or_r4(relative), f"{relative} 는 R4·아트 경로다")

    def test_the_art_path_detector_is_not_vacuous(self) -> None:
        """탐지기가 실제로 무언가를 거부하는지 확인한다. 항상 False인 검사는 검사가 아니다."""

        for sample in (
            "tasks/R4-ART-0007.json",
            "assets/roulette/table.png",
            "docs/art/style-guide.md",
            "games/roulette/images/chip.webp",
        ):
            with self.subTest(sample=sample):
                self.assertTrue(path_is_art_or_r4(sample))
        for sample in ("artifacts/R2-QA-0006-artifact.json", "tests/test_rng.py", STATUS_PATH):
            with self.subTest(sample=sample):
                self.assertFalse(path_is_art_or_r4(sample))


# ---------------------------------------------------------------------------------------
# 2. 다섯 유닛 삼중 계약 (AC-001)
# ---------------------------------------------------------------------------------------


class SourceTripletTests(unittest.TestCase):
    """다섯 유닛의 Task·Artifact·Handoff 15개 문서를 스키마와 정렬 규칙으로 검사한다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {kind: _schema(kind) for kind in SCHEMA_BY_KIND}
        cls.required = required_commands()

    def test_all_fifteen_documents_exist_and_validate(self) -> None:
        seen = 0
        for unit in SOURCE_UNITS:
            task, artifact, handoff = _triplet(unit)
            for kind, document in (("task", task), ("artifact", artifact), ("handoff", handoff)):
                with self.subTest(unit=unit, kind=kind):
                    validate_instance(document, self.schemas[kind])
                    seen += 1
        self.assertEqual(seen, 15)

    def test_identifiers_align_across_the_triplet_and_the_filename(self) -> None:
        for unit in SOURCE_UNITS:
            task, artifact, handoff = _triplet(unit)
            with self.subTest(unit=unit):
                self.assertEqual(task["task_id"], unit, "파일명과 task_id가 어긋난다")
                self.assertEqual(artifact["task_id"], unit)
                self.assertEqual(handoff["task_id"], unit)
                self.assertEqual(artifact["project_id"], task["project_id"])
                self.assertIn(artifact["artifact_id"], handoff["artifact_refs"])

    def test_generator_and_reviewer_stay_separated(self) -> None:
        for unit in SOURCE_UNITS:
            _, artifact, handoff = _triplet(unit)
            with self.subTest(unit=unit):
                self.assertNotIn(artifact["source"]["created_by"], artifact["reviewers"])
                self.assertGreaterEqual(len(artifact["reviewers"]), 1)
                self.assertNotEqual(handoff["from_agent_id"], handoff["to_agent_id"])

    def test_the_two_required_commands_are_recorded_as_pass(self) -> None:
        self.assertEqual(
            self.required,
            ["python scripts/validate_baseline.py", "python -m unittest discover -s tests -v"],
        )
        for unit in SOURCE_UNITS:
            _, _, handoff = _triplet(unit)
            with self.subTest(unit=unit):
                self.assertEqual(missing_evidence_commands(handoff, self.required), [])

    def test_each_handoff_is_independently_verifiable_by_its_receiver(self) -> None:
        for unit in SOURCE_UNITS:
            _, _, handoff = _triplet(unit)
            decision = evaluate_independent_verification(
                handoff, console="codex", verifier_agent_id=handoff["to_agent_id"]
            )
            with self.subTest(unit=unit):
                self.assertTrue(decision.allowed, decision.message)

    def test_each_artifact_primary_binding_matches_its_file(self) -> None:
        for unit in SOURCE_UNITS:
            _, artifact, _ = _triplet(unit)
            relative = _repo_relative(artifact["uri"])
            with self.subTest(unit=unit, uri=artifact["uri"]):
                self.assertIsNotNone(relative)
                assert relative is not None
                self.assertTrue((ROOT / relative).is_file())
                decision = verify_file(ROOT / relative, artifact["content_hash"], label=relative)
                self.assertTrue(decision.matches, decision.message)


class SourceComponentHashTests(unittest.TestCase):
    """유닛별로 다른 해시 키 이름을 실제 이름 그대로 검사한다."""

    def test_every_bound_component_hash_matches_its_file(self) -> None:
        checked = 0
        for unit, bindings in COMPONENT_HASH_BINDINGS.items():
            specification = _read_json(f"artifacts/{unit}-artifact.json")["specification"]
            for key, relative in bindings.items():
                with self.subTest(unit=unit, key=key):
                    self.assertIn(key, specification, f"{unit}: {key} 선언이 사라졌다")
                    self.assertTrue((ROOT / relative).is_file(), f"{relative} 가 없다")
                    decision = verify_file(ROOT / relative, specification[key], label=relative)
                    self.assertTrue(decision.matches, decision.message)
                    checked += 1
        self.assertEqual(checked, sum(len(item) for item in COMPONENT_HASH_BINDINGS.values()))

    def test_no_declared_hash_key_is_left_unchecked(self) -> None:
        """선언된 `sha256:` 키 전부가 묶였거나, 묶이지 않은 이유가 적혀 있어야 한다."""

        for unit in SOURCE_UNITS:
            artifact = _read_json(f"artifacts/{unit}-artifact.json")
            declared = _declared_hash_keys(artifact["specification"])
            covered = set(COMPONENT_HASH_BINDINGS.get(unit, {})) | set(
                UNBOUND_HASH_KEYS.get(unit, {})
            )
            with self.subTest(unit=unit):
                self.assertEqual(
                    declared - covered,
                    set(),
                    f"{unit}: 검사되지 않은 해시 키가 남아 있다",
                )
                self.assertEqual(covered - declared, set(), f"{unit}: 사라진 해시 키를 검사하고 있다")

    def test_the_unbound_key_is_documented_rather_than_silently_skipped(self) -> None:
        for unit, entries in UNBOUND_HASH_KEYS.items():
            specification = _read_json(f"artifacts/{unit}-artifact.json")["specification"]
            for key, reason in entries.items():
                with self.subTest(unit=unit, key=key):
                    self.assertIn(key, specification)
                    self.assertGreater(len(reason), 40, "제외 사유는 실질적으로 적혀야 한다")
        # 폐기 초안은 저장소에 남아 있으면 안 된다.
        self.assertTrue((ROOT / "docs/operations/R2-RNG-0001-recovery.md").is_file())


# ---------------------------------------------------------------------------------------
# 3. 다섯 유닛 감사 기록 (AC-012)
# ---------------------------------------------------------------------------------------


class SourceAuditRecordTests(unittest.TestCase):
    """다섯 유닛의 감사 기록이 스키마에 유효하고 연쇄가 끊기지 않았음을 확인한다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = _read_json(AUDIT_EVENT_SCHEMA_PATH)

    def test_each_record_validates_and_its_chain_holds(self) -> None:
        for unit in SOURCE_UNITS:
            relative = f"audit/events/{unit}-events.json"
            document = _read_json(relative)
            with self.subTest(unit=unit):
                self.assertEqual(document["task_id"], unit)
                self.assertGreaterEqual(len(document["events"]), 1)
                for event in document["events"]:
                    validate_instance(event, self.schema)
                    self.assertEqual(event["task_id"], unit)
                    self.assertIs(event["contains_secret"], False)
                self.assertEqual(verify_audit_chain(document["events"]), [])

    def test_the_records_are_the_ones_the_contract_pinned(self) -> None:
        pinned = {
            _repo_relative(item["uri"]): item["content_hash"]
            for item in _read_json(TASK_PATH)["inputs"]
            if (_repo_relative(item["uri"]) or "").startswith("audit/events/")
        }
        self.assertEqual(len(pinned), 5)
        for relative, declared in pinned.items():
            with self.subTest(record=relative):
                self.assertEqual(hash_file(ROOT / relative, label=relative), declared)


# ---------------------------------------------------------------------------------------
# 4. 이 유닛의 신규 산출물 (AC-006, AC-009, AC-012, AC-013)
# ---------------------------------------------------------------------------------------


class ClosureDeliverableTests(unittest.TestCase):
    """네 신규 구현 산출물이 존재하고 계약의 deliverables와 정확히 대응하는지 본다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.task = _read_json(TASK_PATH)

    def test_all_seven_created_paths_exist(self) -> None:
        self.assertEqual(len(CREATED_PATHS), 7)
        self.assertEqual(len(set(CREATED_PATHS)), 7)
        for relative in CREATED_PATHS:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"{relative} 가 없다")

    def test_the_declared_deliverables_are_exactly_the_six_written_documents(self) -> None:
        declared = {_repo_relative(item["target_uri"]) for item in self.task["deliverables"]}
        self.assertEqual(declared, set(CREATED_PATHS) - {TASK_PATH})

    def test_the_created_paths_are_not_part_of_the_frozen_input_set(self) -> None:
        """가산성: 신규 산출물이 동시에 동결 입력일 수 없다. 그러면 자기 참조가 된다."""

        pinned = {_repo_relative(item["uri"]) for item in self.task["inputs"]}
        self.assertEqual(pinned & set(CREATED_PATHS), set())

    def test_no_other_control_plane_document_declares_these_paths(self) -> None:
        """이 일곱 경로를 참조하는 계약은 이 유닛의 것뿐이어야 한다."""

        offenders: list[str] = []
        for path in sorted((ROOT / "tasks").glob("*.json")):
            if path.name == f"{UNIT_ID}.json":
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
            for item in document.get("inputs", []):
                if _repo_relative(item["uri"]) in CREATED_PATHS:
                    offenders.append(f"tasks/{path.name} -> {item['uri']}")
        for path in sorted((ROOT / "artifacts").glob("*.json")):
            if path.name == f"{UNIT_ID}-artifact.json":
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
            if _repo_relative(document["uri"]) in CREATED_PATHS:
                offenders.append(f"artifacts/{path.name} -> {document['uri']}")
        self.assertEqual(offenders, [])


class ClosureArtifactTests(unittest.TestCase):
    """이 유닛의 Artifact Contract 무결성과 표기 정확성."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.artifact = _read_json(ARTIFACT_PATH)
        cls.specification = cls.artifact["specification"]

    def test_it_validates_against_the_artifact_schema(self) -> None:
        validate_instance(self.artifact, _schema("artifact"))

    def test_the_primary_binding_is_the_closure_candidate_status_document(self) -> None:
        self.assertEqual(self.artifact["uri"], f"repo://{STATUS_PATH}")
        decision = verify_file(ROOT / STATUS_PATH, self.artifact["content_hash"], label=STATUS_PATH)
        self.assertTrue(decision.matches, decision.message)

    def test_it_declares_that_it_represents_the_implementation(self) -> None:
        self.assertIs(self.specification["represents_implementation"], True)
        self.assertEqual(self.specification["represents"], STATUS_PATH)
        self.assertIs(self.specification["implementation_started"], True)
        self.assertIs(self.specification["implementation_completed"], True)
        self.assertEqual(self.specification["implementation_deliverables_declared"], 6)
        self.assertEqual(self.specification["implementation_deliverables_written"], 6)
        self.assertEqual(self.specification["pending_deliverable_count"], 0)

    def test_the_four_component_hashes_match_their_files(self) -> None:
        for key, relative in CLOSURE_COMPONENT_HASH_BINDINGS.items():
            with self.subTest(key=key):
                self.assertIn(key, self.specification)
                decision = verify_file(
                    ROOT / relative, self.specification[key], label=relative
                )
                self.assertTrue(decision.matches, decision.message)
        self.assertEqual(
            self.specification["component_hash_form"],
            "canonical LF (studio_core.integrity.hash_file)",
        )

    def test_no_declared_hash_key_of_this_artifact_is_left_unchecked(self) -> None:
        declared = _declared_hash_keys(self.specification)
        covered = set(CLOSURE_COMPONENT_HASH_BINDINGS) | {"task_contract_hash"}
        self.assertEqual(declared - covered, set(), "검사되지 않은 해시 키가 남아 있다")
        self.assertEqual(
            hash_file(ROOT / TASK_PATH, label=TASK_PATH), self.specification["task_contract_hash"]
        )
        self.assertEqual(self.artifact["source"]["input_hash"], self.specification["task_contract_hash"])

    def test_the_declared_cross_verification_counts_match_what_is_checked(self) -> None:
        """선언한 검사 건수가 실제 검사 건수와 같아야 한다. 숫자는 셀 수 있어야 주장이 된다."""

        self.assertEqual(
            self.specification["cross_verification_component_hash_keys_checked"],
            sum(len(bindings) for bindings in COMPONENT_HASH_BINDINGS.values()),
        )
        self.assertEqual(
            self.specification["cross_verification_unbound_hash_keys_documented"],
            sum(len(entries) for entries in UNBOUND_HASH_KEYS.values()),
        )
        self.assertEqual(self.specification["cross_verification_triplet_documents"], 15)
        self.assertEqual(
            self.specification["cross_verification_audit_records_checked"], len(SOURCE_UNITS) + 1
        )
        self.assertEqual(
            self.specification["audit_chain_events"], len(_read_json(EVENTS_PATH)["events"])
        )
        self.assertEqual(self.specification["known_limits_count"], len(KNOWN_LIMIT_MARKERS))

    def test_provenance_is_recorded_truthfully(self) -> None:
        source = self.artifact["source"]
        self.assertEqual(source["kind"], "AI_GENERATED")
        self.assertEqual(source["created_by"], "A-20")
        self.assertEqual(source["provider"], "claude_agent")
        self.assertEqual(source["model"], "claude-opus-5[1m]")
        self.assertEqual(self.specification["code_generation_provider"], "claude_agent")
        self.assertIs(self.specification["provider_substitution_occurred"], False)

    def test_the_creator_is_excluded_from_the_reviewers(self) -> None:
        self.assertEqual(self.artifact["reviewers"], ["A-50", "A-02"])
        self.assertNotIn(self.artifact["source"]["created_by"], self.artifact["reviewers"])

    def test_the_closure_status_is_a_candidate_and_never_a_completion(self) -> None:
        self.assertEqual(self.specification["closure_status"], CLOSURE_STATUS)
        self.assertIs(self.specification["closure_status_is_done"], False)
        self.assertIs(self.specification["closure_status_is_closed"], False)
        self.assertIs(self.specification["closure_status_is_production_ready"], False)
        self.assertIs(self.specification["production_ready"], False)

    def test_every_gate_field_stays_unissued(self) -> None:
        for key, expected in PENDING_GATE_FIELDS.items():
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], expected)
        self.assertIs(self.specification["qa_pass_verdict_claimed_by_claude"], False)
        self.assertIs(self.specification["human_approved"], False)
        self.assertIs(self.specification["approver_signatures_collected"], False)
        self.assertIsNone(self.artifact["approved_at"])

    def test_the_artifact_status_stops_short_of_qa_passed_and_approved(self) -> None:
        """독립 검증을 거친 상태는 `REVIEWED`다. `QA_PASSED`도 `APPROVED`도 아니다."""

        self.assertEqual(self.artifact["status"], "REVIEWED")
        self.assertNotIn(self.artifact["status"], {"QA_PASSED", "APPROVED", "ENGINE_READY"})

    def test_the_user_start_authorization_is_not_a_final_qa_signoff(self) -> None:
        self.assertIs(self.specification["user_start_authorization_granted"], True)
        self.assertIs(self.specification["user_start_authorization_is_final_qa_signoff"], False)
        self.assertEqual(self.specification["user_final_approval"], "NOT_RUN")
        self.assertEqual(self.specification["a00_gate_decision"], "NOT_RUN")

    def test_the_additive_boundary_is_declared_and_consistent(self) -> None:
        self.assertEqual(self.specification["existing_files_modified"], 0)
        self.assertIs(self.specification["additive_only"], True)
        self.assertEqual(self.specification["integrity_repin_of_existing_contracts"], 0)
        self.assertEqual(self.specification["files_created_by_this_unit"], 7)
        self.assertIs(self.specification["validate_baseline_modified"], False)
        for key in (
            "existing_tasks_rewritten",
            "existing_artifacts_rewritten",
            "existing_handoffs_rewritten",
            "existing_approval_reports_rewritten",
            "existing_status_files_rewritten",
        ):
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], 0)
        self.assertIs(self.specification["production_runtime_code_modified"], False)

    def test_the_r4_boundary_is_declared_untouched(self) -> None:
        for key in (
            "r4_art_0007_touched",
            "r4_art_0007_closure_claimed",
            "r4_art_0007_pinned_or_delivered_by_this_unit",
            "r4_deliverables_touched",
            "asset_or_image_paths_touched",
            "art_created_by_claude",
            "art_reviewed_by_claude",
        ):
            with self.subTest(field=key):
                self.assertIs(self.specification[key], False)
        self.assertEqual(self.specification["r4_art_rights_and_integration_status"], "SEPARATE_AND_BLOCKED")

    def test_the_six_known_limits_are_declared_with_their_counts(self) -> None:
        for key in (
            "known_limit_single_user_local_reference_scope",
            "known_limit_no_production_or_external_environment",
            "known_limit_no_slo_or_capacity_promise",
            "known_limit_r5_schedule_prohibition",
            "known_limit_stale_temp_workspaces_remain_local_cleanup_debt",
        ):
            with self.subTest(field=key):
                self.assertIs(self.specification[key], True)
        self.assertEqual(
            self.specification["known_limit_stale_temp_workspaces_from_r2_load_0004"],
            STALE_WORKSPACE_COUNT,
        )
        self.assertEqual(
            self.specification["known_limit_stale_temp_workspace_prefix"], STALE_WORKSPACE_PREFIX
        )
        self.assertIs(
            self.specification["known_limit_stale_temp_workspaces_independently_shown_removed"],
            False,
        )
        self.assertEqual(
            self.specification["known_limit_r2_sec_current_runs_leftover_workspaces"],
            SEC_LEFTOVER_WORKSPACE_COUNT,
        )
        self.assertIs(self.specification["absolute_temp_path_recorded"], False)

    def test_the_stale_workspace_debt_agrees_with_the_load_unit(self) -> None:
        load = _read_json("artifacts/R2-LOAD-0004-artifact.json")["specification"]
        self.assertEqual(load["stale_pre_fix_temporary_workspaces"], STALE_WORKSPACE_COUNT)
        self.assertEqual(load["stale_workspace_prefix"], STALE_WORKSPACE_PREFIX)
        self.assertIs(load["stale_workspaces_removed_in_this_unit"], False)
        self.assertIs(load["stale_workspaces_pending_explicit_cleanup"], True)
        security = _read_json("artifacts/R2-SEC-0005-artifact.json")["specification"]
        self.assertEqual(
            security["temporary_workspaces_left_behind"], SEC_LEFTOVER_WORKSPACE_COUNT
        )


class ClosureHandoffTests(unittest.TestCase):
    """이 유닛의 Handoff Packet이 A-20에서 A-50으로 가는 정직한 전달인지 본다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.handoff = _read_json(HANDOFF_PATH)
        cls.artifact = _read_json(ARTIFACT_PATH)

    def test_it_validates_and_addresses_the_reviewer(self) -> None:
        validate_instance(self.handoff, _schema("handoff"))
        self.assertEqual(self.handoff["from_agent_id"], "A-20")
        self.assertEqual(self.handoff["to_agent_id"], "A-50")
        self.assertNotEqual(self.handoff["from_agent_id"], self.handoff["to_agent_id"])
        self.assertIn(self.artifact["artifact_id"], self.handoff["artifact_refs"])

    def test_readiness_is_ready_for_qa_after_the_independent_verification(self) -> None:
        """`READY_FOR_QA`는 최종 QA 게이트를 기다린다는 뜻이지 통과했다는 뜻이 아니다."""

        self.assertEqual(self.handoff["readiness"], "READY_FOR_QA")
        self.assertIn(
            self.handoff["readiness"],
            load_yaml("operations/collaboration.yaml")["completion_gate"]["allowed_readiness"],
        )
        self.assertIs(self.handoff["acknowledgement_required"], True)
        self.assertEqual(
            self.artifact["specification"]["a20_standard_commands_run_against_readiness"],
            self.handoff["readiness"],
        )
        self.assertEqual(self.artifact["specification"]["a50_qa_gate_decision"], "NOT_RUN")

    def test_the_two_standard_commands_carry_pass_records(self) -> None:
        self.assertEqual(missing_evidence_commands(self.handoff, required_commands()), [])

    def test_it_is_independently_verifiable_by_a50_on_the_verifier_console(self) -> None:
        decision = evaluate_independent_verification(
            self.handoff, console="codex", verifier_agent_id="A-50"
        )
        self.assertTrue(decision.allowed, decision.message)

    def test_the_generator_cannot_verify_or_approve_its_own_work(self) -> None:
        self_verify = evaluate_independent_verification(
            self.handoff, console="codex", verifier_agent_id="A-20"
        )
        self.assertFalse(self_verify.allowed)
        self.assertEqual(self_verify.code, "SELF_VERIFICATION_DENIED")

    def test_no_gate_verdict_is_recorded_as_issued(self) -> None:
        """게이트 행은 접두사로 표시되고, 표시된 행은 예외 없이 `NOT_RUN`이어야 한다.

        "A-50"이라는 문자열의 등장 여부로 판정할 수는 없다. 이 패킷에는 `A-50`이 **공급한**
        증거를 `PASS`로 옮긴 행이 여럿 있고, 그것은 게이트 판정이 아니라 전달받은 관측이다.
        두 종류를 구분하려면 표시가 필요하다.
        """

        gated = [
            record
            for record in self.handoff["verification_evidence"]
            if record["check"].startswith(GATE_ROW_PREFIX)
        ]
        self.assertGreaterEqual(len(gated), 5)
        for record in gated:
            with self.subTest(check=record["check"][:70]):
                self.assertEqual(record["result"], "NOT_RUN")
        gated_text = " ".join(record["check"] for record in gated)
        for owner in ("A-50", "A-02", "A-00", "USER"):
            with self.subTest(owner=owner):
                self.assertIn(owner, gated_text)

    def test_supplied_evidence_rows_are_labelled_as_supplied(self) -> None:
        """`A-50`이 공급한 값을 옮긴 행은 출처를 밝히고, 그 사실이 게이트로 읽히지 않아야 한다."""

        supplied = [
            record
            for record in self.handoff["verification_evidence"]
            if record["check"].startswith(SUPPLIED_ROW_PREFIX)
        ]
        self.assertGreaterEqual(len(supplied), 9)
        for record in supplied:
            with self.subTest(check=record["check"][:70]):
                self.assertEqual(record["result"], "PASS")
                self.assertFalse(record["check"].startswith(GATE_ROW_PREFIX))

    def test_the_delegation_gate_still_admits_this_contract(self) -> None:
        decision = evaluate_delegation(
            _read_json(TASK_PATH), console="claude_code", actor_agent_id="A-20"
        )
        self.assertTrue(decision.allowed, decision.message)
        self.assertEqual(decision.code, "DELEGATED")


class ClosureAuditRecordTests(unittest.TestCase):
    """이 유닛 감사 기록의 스키마 유효성, 연쇄, 파생 가능한 request_hash."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = _read_json(EVENTS_PATH)
        cls.events = cls.document["events"]
        cls.schema = _read_json(AUDIT_EVENT_SCHEMA_PATH)

    def test_the_record_header_names_this_unit(self) -> None:
        self.assertEqual(self.document["schema_version"], "1.0.0")
        self.assertEqual(self.document["task_id"], UNIT_ID)
        self.assertEqual(self.document["chain_namespace"], "R2QA")
        self.assertGreaterEqual(len(self.events), 8)

    def test_every_event_validates_and_carries_no_secret(self) -> None:
        for event in self.events:
            with self.subTest(event=event["event_id"]):
                validate_instance(event, self.schema)
                self.assertEqual(event["task_id"], UNIT_ID)
                self.assertIs(event["contains_secret"], False)
                self.assertTrue(event["event_id"].startswith("AE-R2QA-"))

    def test_event_identifiers_are_sequential_and_unique(self) -> None:
        ids = [event["event_id"] for event in self.events]
        self.assertEqual(ids, [f"AE-R2QA-{index:04d}" for index in range(1, len(ids) + 1)])

    def test_the_chain_links_and_verifies(self) -> None:
        self.assertEqual(verify_audit_chain(self.events), [])
        self.assertIsNone(self.events[0]["previous_event_hash"])

    def test_the_chain_verifier_is_not_vacuous(self) -> None:
        """연쇄 검증기가 실제로 조작을 잡는지 폐기 가능한 사본에서 확인한다."""

        forged = json.loads(json.dumps(self.events))
        forged[-1]["action"] = "TAMPERED_ACTION_VALUE"
        self.assertNotEqual(verify_audit_chain(forged), [])

    def test_each_request_hash_is_derivable_from_the_event_it_describes(self) -> None:
        for event in self.events:
            with self.subTest(event=event["event_id"]):
                self.assertEqual(
                    event["request_hash"], canonical_request_hash(request_descriptor(event))
                )

    def test_no_resource_reference_reaches_r4_art_assets_or_images(self) -> None:
        for event in self.events:
            for reference in event["resource_refs"]:
                relative = _repo_relative(reference)
                if relative is None:
                    continue
                with self.subTest(event=event["event_id"], reference=reference):
                    self.assertFalse(path_is_art_or_r4(relative))

    def test_the_record_keeps_the_unissued_gates_visible(self) -> None:
        actions = {event["action"] for event in self.events}
        self.assertIn("CLOSURE_STATUS_RECORDED_CLOSED_PENDING_DIRECTOR_AND_USER", actions)
        self.assertIn("FINAL_QA_GATES_AND_HOSTED_CI_NOT_RUN", actions)
        blocking = [event for event in self.events if event["decision"] == "BLOCK"]
        self.assertGreaterEqual(len(blocking), 2)


# ---------------------------------------------------------------------------------------
# 5. 보고서와 상태 문서 (AC-003, AC-004, AC-006, AC-007, AC-013)
# ---------------------------------------------------------------------------------------


class ClosureNarrativeTests(unittest.TestCase):
    """보고서와 상태 문서가 기록해야 할 사실을 실제로 담고 있는지 본다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _read_text(REPORT_PATH)
        cls.status = _read_text(STATUS_PATH)

    def test_the_closure_status_appears_and_the_prohibited_ones_do_not(self) -> None:
        for document, label in ((self.report, "report"), (self.status, "status")):
            with self.subTest(document=label):
                self.assertIn(CLOSURE_STATUS, document)
                for prohibited in PROHIBITED_CLOSURE_STATUSES:
                    pattern = rf"상태(?:\s*값)?\s*(?:은|는|이)\s*`?{prohibited}`?\s*(?:이다|다)"
                    self.assertIsNone(
                        re.search(pattern, document),
                        f"{label}: 금지된 종결 상태 {prohibited} 를 주장한다",
                    )

    def test_the_unissued_gates_are_stated_next_to_the_status(self) -> None:
        for document, label in ((self.report, "report"), (self.status, "status")):
            with self.subTest(document=label):
                for marker in (
                    "`A-50` 최종 QA 게이트 판정: `NOT_RUN`",
                    "`A-02` 게이트 판정",
                    "`A-00` 게이트 판정: `NOT_RUN`",
                    "`USER` 최종 QA 승인: `NOT_RUN`",
                ):
                    self.assertIn(marker, document)

    def test_the_issued_verdict_is_stated_next_to_the_unissued_gates(self) -> None:
        """발행된 판정과 미발행 게이트가 같은 문서에서 함께 읽혀야 한다.

        둘 중 하나만 남으면 문서는 둘 중 한쪽으로 잘못 인용된다. `PASS`만 남으면 승인으로,
        `NOT_RUN`만 남으면 독립 검증이 없었던 것으로 읽힌다.
        """

        for document, label in ((self.report, "report"), (self.status, "status")):
            with self.subTest(document=label):
                self.assertIn(f"독립 검증 판정: `{INDEPENDENT_VERIFICATION_VERDICT}`", document)
                self.assertIn("`FINAL_GATE`가", document)
                self.assertIn("`USER` 최종 QA 승인: `NOT_RUN`", document)

    def test_the_six_known_limits_are_present_in_full(self) -> None:
        for marker in KNOWN_LIMIT_MARKERS:
            with self.subTest(limit=marker):
                self.assertIn(marker, self.report)
                self.assertIn(marker.split(":", 1)[1].strip(), self.status)

    def test_the_stale_workspace_debt_is_recorded_without_absolute_paths(self) -> None:
        self.assertIn(f"{STALE_WORKSPACE_COUNT}건", self.report)
        self.assertIn(STALE_WORKSPACE_PREFIX, self.report)
        for document, label in ((self.report, "report"), (self.status, "status")):
            for pattern in ABSOLUTE_PATH_PATTERNS:
                with self.subTest(document=label, pattern=pattern):
                    self.assertIsNone(re.search(pattern, document))

    def test_the_supplied_evidence_is_attributed_and_not_claimed_as_fetched(self) -> None:
        self.assertIn(HOSTED_CI_EVIDENCE_SOURCE, self.report)
        for marker in (
            "Claude는 이 값을 재조회하지 않았다",
            "네트워크에 접근하지 않았다",
            "A-20 자체 점검",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.report)

    def test_the_a50_supplied_pre_contract_numbers_are_carried_over(self) -> None:
        for marker in (
            "405",
            "20단계",
            "792",
            "4건 건너뜀",
            "216개 파일",
            "f564bce",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.report)

    def test_no_production_slo_or_schedule_promise_is_made(self) -> None:
        for document, label in ((self.report, "report"), (self.status, "status")):
            with self.subTest(document=label):
                for pattern in (
                    r"출시일\s*(?:은|는)\s*\d",
                    r"SLO\s*(?:는|은)\s*\d",
                    r"목표\s*지연\s*시간\s*\d",
                    r"배포\s*일정\s*확정",
                ):
                    self.assertIsNone(re.search(pattern, document))
                self.assertIn("R5", document)

    def test_the_art_work_is_named_as_out_of_scope_without_pinning_a_path(self) -> None:
        self.assertIn("SEPARATE_AND_BLOCKED", self.report)
        for document in (self.report, self.status):
            for match in re.findall(r"repo://([A-Za-z0-9._/-]+)", document):
                with self.subTest(reference=match):
                    self.assertFalse(path_is_art_or_r4(match))


class HostedCiEvidenceTests(unittest.TestCase):
    """AC-004: 다섯 PR 증거가 문자 단위로 그대로 표현되었는지."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _read_text(REPORT_PATH)
        cls.specification = _read_json(ARTIFACT_PATH)["specification"]
        cls.handoff_text = _read_text(HANDOFF_PATH)
        cls.events_text = _read_text(EVENTS_PATH)

    def test_exactly_five_pull_requests_are_recorded(self) -> None:
        self.assertEqual(len(HOSTED_CI_PR_RECORDS), 5)
        self.assertEqual(self.specification["hosted_ci_evidence_pr_count"], 5)
        self.assertEqual(self.specification["hosted_ci_checks_per_pr"], 3)
        self.assertEqual(self.specification["hosted_ci_repository"], HOSTED_CI_REPOSITORY)

    def test_every_supplied_field_appears_verbatim_in_the_report_and_the_artifact(self) -> None:
        for record in HOSTED_CI_PR_RECORDS:
            key = f"hosted_ci_pr_{record['unit'].lower().replace('-', '_')}"
            declared = self.specification[key]
            for field in ("url", "merged_at", "merge_commit"):
                with self.subTest(unit=record["unit"], field=field):
                    self.assertIn(record[field], declared)
                    self.assertIn(record[field], self.report)
            with self.subTest(unit=record["unit"], field="number"):
                self.assertIn(f"PR #{record['number']}", declared)
                self.assertIn(f"PR #{record['number']}", self.report)

    def test_the_three_check_names_are_the_workflow_job_names(self) -> None:
        workflow = _read_text(".github/workflows/ci.yml")
        self.assertIn("Baseline, tests and compile (Python ${{ matrix.python-version }})", workflow)
        self.assertIn("Repository secret scan", workflow)
        for name in HOSTED_CI_CHECK_NAMES:
            with self.subTest(check=name):
                self.assertIn(name, self.report)
        self.assertGreaterEqual(self.report.count(HOSTED_CI_CHECK_CONCLUSION), 5)

    def test_the_source_is_declared_and_no_requery_is_claimed(self) -> None:
        self.assertEqual(
            self.specification["hosted_ci_evidence_source"], HOSTED_CI_EVIDENCE_SOURCE
        )
        self.assertIs(self.specification["hosted_ci_evidence_requeried_by_claude"], False)
        self.assertIs(self.specification["network_access_performed"], False)
        self.assertIn(HOSTED_CI_EVIDENCE_SOURCE, self.handoff_text)
        self.assertIn(HOSTED_CI_EVIDENCE_SOURCE, self.events_text)

    def test_the_supplied_run_counts_are_carried_over_unchanged(self) -> None:
        for key, expected in A50_SUPPLIED_RUN_FACTS.items():
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], expected)
        self.assertEqual(self.specification["base_commit_full"], A50_SUPPLIED_BASE_COMMIT)
        self.assertIs(self.specification["a50_supplied_evidence_replayed_by_claude"], False)
        self.assertIs(self.specification["a50_supplied_evidence_recorded_verbatim"], True)


# ---------------------------------------------------------------------------------------
# 6. 독립 검증 판정의 전사 (AC-005, AC-013)
# ---------------------------------------------------------------------------------------


class IndependentVerificationVerdictTests(unittest.TestCase):
    """공급된 독립 검증 판정이 그대로 남았는지, 그리고 그 판정이 구현자의 것이 아닌지.

    이 시험은 판정의 진위를 확인하지 않는다. 판정은 `codex` 콘솔이 발행했고 `A-20`은 옮겨
    적었을 뿐이다. 여기서 보는 것은 두 가지다. 첫째, 공급된 값이 다섯 산출물에 같은 값으로
    남았는가. 둘째, 발행 주체가 구현자로 둔갑하지 않았고 이 판정이 최종 게이트로 승격되지
    않았는가.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.artifact = _read_json(ARTIFACT_PATH)
        cls.specification = cls.artifact["specification"]
        cls.handoff = _read_json(HANDOFF_PATH)
        cls.report = _read_text(REPORT_PATH)
        cls.status = _read_text(STATUS_PATH)
        cls.events = _read_json(EVENTS_PATH)["events"]

    def test_the_artifact_records_the_supplied_verdict_verbatim(self) -> None:
        self.assertIs(self.specification["independent_verification_completed"], True)
        for key, expected in (
            ("independent_verification_verdict", INDEPENDENT_VERIFICATION_VERDICT),
            ("independent_verification_console", INDEPENDENT_VERIFICATION_CONSOLE),
            ("independent_verification_role", INDEPENDENT_VERIFICATION_ROLE),
            ("independent_verification_acts_for", INDEPENDENT_VERIFICATION_ACTS_FOR),
            ("independent_verification_date", INDEPENDENT_VERIFICATION_DATE),
            ("closure_candidate_recommendation", CLOSURE_CANDIDATE_RECOMMENDATION),
        ):
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], expected)

    def test_the_recorded_scope_is_the_seven_new_files_and_no_tracked_modification(self) -> None:
        self.assertEqual(
            self.specification["independent_verification_scope_files_reviewed"],
            INDEPENDENT_VERIFICATION_SCOPE_FILE_COUNT,
        )
        self.assertEqual(
            self.specification["independent_verification_scope_files_reviewed"],
            self.specification["files_created_by_this_unit"],
        )
        self.assertEqual(
            self.specification["independent_verification_tracked_files_modified"],
            INDEPENDENT_VERIFICATION_TRACKED_FILES_MODIFIED,
        )
        self.assertEqual(
            self.specification["independent_verification_tracked_files_modified"],
            self.specification["existing_files_modified"],
        )

    def test_the_supplied_independent_run_counts_are_carried_over_unchanged(self) -> None:
        for key, expected in INDEPENDENT_SUPPLIED_RUN_FACTS.items():
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], expected)
        self.assertEqual(self.specification["independent_verification_compileall_result"], "PASS")

    def test_the_untouched_measurements_agree_across_both_observers(self) -> None:
        """전사가 건드리지 않은 수치는 두 관측에서 같아야 한다.

        다섯 원천 시험 모듈과 기준선 검증기 단계는 이 전사가 바꾸지 않았다. 그 수치가
        어긋난다면 둘 중 하나가 틀렸거나 무언가가 조용히 바뀐 것이다.
        """

        for independent_key, self_key in (
            ("independent_verification_focused_r2_suite_tests", "a20_focused_five_unit_suite_tests"),
            ("independent_verification_baseline_stages_passed", "a20_baseline_validator_stages_passed"),
            ("independent_verification_full_suite_skipped", "a20_full_suite_skipped"),
            ("independent_verification_secret_scan_files", "a20_secret_scan_files"),
            ("independent_verification_secret_scan_findings", "a20_secret_scan_findings"),
        ):
            with self.subTest(field=independent_key):
                self.assertEqual(
                    self.specification[independent_key], self.specification[self_key]
                )

    def test_the_verdict_is_scoped_to_the_revision_it_actually_saw(self) -> None:
        """판정은 전사 이전 개정을 본 것이다. 전사가 그 사실을 지워서는 안 된다.

        판정을 기록하는 행위 자체가 산출물을 바꾼다. 그래서 독립 검증자가 센 종결 스위트
        건수와 전사 이후의 건수는 같을 수 없고, 같다고 적으면 둘 중 하나가 거짓이 된다.
        여기서 강제하는 것은 그 차이를 감추지 않는 것이다.
        """

        self.assertIs(
            self.specification["independent_verification_covers_this_transcription_revision"],
            False,
        )
        self.assertIn("2.0.0", self.specification["independent_verification_revision_verified"])
        self.assertEqual(self.artifact["version"], "2.1.0")
        self.assertLess(
            self.specification["independent_verification_closure_suite_tests"],
            self.specification["a20_focused_closure_suite_tests"],
        )
        self.assertLess(
            self.specification["independent_verification_full_suite_tests"],
            self.specification["a20_full_suite_tests"],
        )
        self.assertIn("전사", self.specification["independent_verification_observed_state"])

    def test_the_verdict_is_attributed_to_the_verifier_and_not_to_the_implementer(self) -> None:
        self.assertIs(
            self.specification["independent_verification_verdict_issued_by_claude"], False
        )
        self.assertIs(
            self.specification["independent_verification_performed_by_claude"], False
        )
        self.assertEqual(self.specification["independent_verification_verdict_recorded_by"], "A-20")
        self.assertEqual(self.artifact["source"]["created_by"], "A-20")
        self.assertNotEqual(
            self.specification["independent_verification_acts_for"],
            self.artifact["source"]["created_by"],
        )
        self.assertEqual(
            self.specification["a20_implementation_verification"],
            "SELF_CHECK_ONLY_NOT_INDEPENDENT",
        )

    def test_the_recorded_console_and_role_match_the_collaboration_protocol(self) -> None:
        """기록된 발행 주체가 프로토콜의 `independent_verifier` 정의와 어긋나지 않아야 한다."""

        protocol = load_yaml("operations/collaboration.yaml")
        verifier = protocol["roles"][INDEPENDENT_VERIFICATION_ROLE]
        implementer = protocol["roles"]["implementer"]
        self.assertEqual(verifier["console"], INDEPENDENT_VERIFICATION_CONSOLE)
        self.assertIn(INDEPENDENT_VERIFICATION_ACTS_FOR, verifier["acts_for"])
        self.assertNotEqual(verifier["console"], implementer["console"])
        self.assertEqual(verifier["code_generation"], "denied")
        # 검증자도 최종 QA를 판정할 수 없다. 그래서 이 PASS는 최종 게이트가 아니다.
        self.assertEqual(verifier["final_qa_approval"], "denied")
        self.assertEqual(implementer["independent_verification"], "denied")

    def test_the_verdict_does_not_open_the_final_gate(self) -> None:
        self.assertIs(self.specification["independent_verification_is_final_gate"], False)
        self.assertIs(self.specification["independent_verification_is_user_approval"], False)
        self.assertEqual(self.specification["closure_status"], CLOSURE_STATUS)
        for key, expected in PENDING_GATE_FIELDS.items():
            with self.subTest(field=key):
                self.assertEqual(self.specification[key], expected)
        self.assertIs(self.specification["production_ready"], False)
        self.assertIsNone(self.artifact["approved_at"])

    def test_the_handoff_carries_the_supplied_independent_rows(self) -> None:
        rows = [
            record
            for record in self.handoff["verification_evidence"]
            if record["check"].startswith(INDEPENDENT_ROW_PREFIX)
        ]
        self.assertGreaterEqual(len(rows), 7)
        for record in rows:
            with self.subTest(check=record["check"][:70]):
                self.assertEqual(record["result"], "PASS")
                self.assertFalse(record["check"].startswith(GATE_ROW_PREFIX))
                self.assertFalse(record["check"].startswith(SUPPLIED_ROW_PREFIX))
        joined = " ".join(record["check"] for record in rows)
        for marker in (
            INDEPENDENT_VERIFICATION_CONSOLE,
            INDEPENDENT_VERIFICATION_ROLE,
            INDEPENDENT_VERIFICATION_VERDICT,
            CLOSURE_CANDIDATE_RECOMMENDATION,
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, joined)

    def test_the_handoff_no_longer_lists_independent_verification_as_unissued(self) -> None:
        """수행된 단계를 미발행 게이트 행으로 남겨 두면 기록이 사실과 어긋난다."""

        gated = " ".join(
            record["check"]
            for record in self.handoff["verification_evidence"]
            if record["check"].startswith(GATE_ROW_PREFIX)
        )
        self.assertNotIn("독립 구현 검증", gated)
        self.assertIn("최종 QA 게이트", gated)

    def test_the_report_and_the_status_document_state_the_same_verdict(self) -> None:
        for document, label in ((self.report, "report"), (self.status, "status")):
            with self.subTest(document=label):
                self.assertIn(f"독립 검증 판정: `{INDEPENDENT_VERIFICATION_VERDICT}`", document)
                self.assertIn(
                    f"종결 후보 권고: `{CLOSURE_CANDIDATE_RECOMMENDATION}`", document
                )
                self.assertIn(INDEPENDENT_VERIFICATION_CONSOLE, document)
                self.assertIn(INDEPENDENT_VERIFICATION_ROLE, document)
                self.assertIn(INDEPENDENT_VERIFICATION_DATE, document)

    def test_the_report_keeps_the_independent_run_counts(self) -> None:
        for marker in ("84 tests OK", "405 tests OK", "20 PASS, 0 FAIL", "876 tests OK, skipped=4"):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.report)

    def test_the_audit_chain_records_the_verdict_as_its_own_event(self) -> None:
        matches = [
            event for event in self.events if event["action"] == INDEPENDENT_VERDICT_EVENT_ACTION
        ]
        self.assertEqual(len(matches), 1)
        event = matches[0]
        self.assertEqual(event["actor_id"], INDEPENDENT_VERIFICATION_ACTS_FOR)
        self.assertEqual(event["actor_type"], "AGENT")
        self.assertEqual(event["decision"], "COMPLETE")
        self.assertEqual(event["event_id"], f"AE-R2QA-{len(self.events):04d}")
        self.assertEqual(event["timestamp"][: len(INDEPENDENT_VERIFICATION_DATE)], INDEPENDENT_VERIFICATION_DATE)
        # 판정 이벤트가 붙어도 앞선 BLOCK 두 건은 그대로 남아 있어야 한다.
        self.assertEqual(
            len([item for item in self.events if item["decision"] == "BLOCK"]), 2
        )

    def test_this_module_still_refuses_to_produce_a_verdict_of_its_own(self) -> None:
        """산출물에 `ISSUED`가 기록되었다고 해서 이 모듈이 판정을 만들지는 않는다."""

        decision = evaluate_closure_readiness(
            {"frozen_inputs": "PASS", "audit_chain": "PASS", "closure_documents": "PASS"}
        )
        self.assertEqual(decision.qa_pass_recommendation, "NOT_RUN")
        self.assertEqual(decision.final_gate_owners, ("A-50", "USER"))


# ---------------------------------------------------------------------------------------
# 7. 판정 주체 경계 (AC-005)
# ---------------------------------------------------------------------------------------


class VerdictBoundaryTests(unittest.TestCase):
    """구현자는 최종 QA를 판정할 수 없고, 산출물은 그 판정을 자칭하지 않는다."""

    def test_the_implementer_role_is_denied_the_final_qa_approval(self) -> None:
        decision = evaluate_role_action("implementer", "final_qa_approval")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "ACTION_DENIED")

    def test_the_implementer_role_is_denied_independent_verification(self) -> None:
        decision = evaluate_role_action("implementer", "independent_verification")
        self.assertFalse(decision.allowed)

    def test_no_deliverable_claims_a_qa_pass_verdict(self) -> None:
        for relative in CREATED_PATHS:
            text = _read_text(relative)
            for pattern in SELF_APPROVAL_PATTERNS:
                with self.subTest(path=relative, pattern=pattern):
                    self.assertIsNone(
                        re.search(pattern, text), f"{relative}: 자기 QA 판정 문구가 있다"
                    )

    def test_the_issued_recommendation_is_scoped_and_not_a_final_gate(self) -> None:
        """권고가 발행되었다는 기록은 그 권고가 무엇을 덮는지와 함께 남아야 한다."""

        specification = _read_json(ARTIFACT_PATH)["specification"]
        self.assertEqual(
            specification["closure_candidate_recommendation"], CLOSURE_CANDIDATE_RECOMMENDATION
        )
        self.assertEqual(
            specification["closure_candidate_recommendation_issued_by"],
            "codex console acting in the independent_verifier role for A-50",
        )
        self.assertIs(specification["closure_candidate_recommendation_is_final_gate"], False)
        scope_note = specification["closure_candidate_recommendation_scope_note"]
        self.assertIn("FINAL_GATE", scope_note)
        self.assertGreater(len(scope_note), 60)
        self.assertEqual(specification["a50_qa_gate_decision"], "NOT_RUN")
        self.assertEqual(specification["user_final_approval"], "NOT_RUN")

    def test_the_implementer_is_never_recorded_as_the_verifier(self) -> None:
        specification = _read_json(ARTIFACT_PATH)["specification"]
        self.assertIs(specification["qa_pass_verdict_claimed_by_claude"], False)
        self.assertIs(specification["independent_verification_verdict_issued_by_claude"], False)
        self.assertIs(specification["independent_verification_performed_by_claude"], False)
        self.assertEqual(specification["code_generation_provider"], "claude_agent")
        # 검증자는 코드를 만들지 않았고 구현자는 검증하지 않았다. 두 경계가 모두 필요하다.
        self.assertIs(specification["provider_substitution_occurred"], False)


# ---------------------------------------------------------------------------------------
# 8. 실패 강제 경로 (AC-011)
# ---------------------------------------------------------------------------------------


class ReworkEnforcementTests(unittest.TestCase):
    """실패한 검증 결과가 종결 권고를 차단하고 REWORK_REQUIRED를 강제하는지."""

    def _all_pass(self) -> dict[str, str]:
        return {
            "frozen_inputs": "PASS",
            "source_triplets": "PASS",
            "component_hashes": "PASS",
            "audit_chain": "PASS",
            "closure_documents": "PASS",
            "hosted_ci_transcription": "PASS",
        }

    def test_a_fully_passing_input_yields_a_closure_candidate_recommendation(self) -> None:
        decision = evaluate_closure_readiness(self._all_pass())
        self.assertEqual(decision.readiness, "READY_FOR_REVIEW")
        self.assertTrue(decision.closure_candidate_recommended)
        self.assertEqual(decision.closure_status, CLOSURE_STATUS)
        self.assertEqual(decision.blocked_by, ())

    def test_even_a_fully_passing_input_never_produces_a_qa_verdict(self) -> None:
        decision = evaluate_closure_readiness(self._all_pass())
        self.assertEqual(decision.qa_pass_recommendation, "NOT_RUN")
        self.assertEqual(decision.final_gate_owners, ("A-50", "USER"))
        self.assertNotIn(decision.closure_status, PROHIBITED_CLOSURE_STATUSES)

    def test_a_single_synthetic_failure_blocks_the_recommendation(self) -> None:
        for failing in sorted(self._all_pass()):
            results = self._all_pass()
            results[failing] = "FAIL"
            decision = evaluate_closure_readiness(results)
            with self.subTest(failing=failing):
                self.assertEqual(decision.readiness, "REWORK_REQUIRED")
                self.assertFalse(decision.closure_candidate_recommended)
                self.assertIsNone(decision.closure_status)
                self.assertEqual(decision.blocked_by, (failing,))
                self.assertEqual(decision.qa_pass_recommendation, "NOT_RUN")

    def test_a_not_run_result_is_not_treated_as_a_pass(self) -> None:
        results = self._all_pass()
        results["audit_chain"] = "NOT_RUN"
        decision = evaluate_closure_readiness(results)
        self.assertEqual(decision.readiness, "REWORK_REQUIRED")
        self.assertFalse(decision.closure_candidate_recommended)

    def test_an_empty_result_set_cannot_be_read_as_success(self) -> None:
        decision = evaluate_closure_readiness({})
        self.assertEqual(decision.readiness, "REWORK_REQUIRED")
        self.assertFalse(decision.closure_candidate_recommended)

    def test_multiple_failures_are_all_reported(self) -> None:
        results = self._all_pass()
        results["frozen_inputs"] = "FAIL"
        results["audit_chain"] = "ERROR"
        decision = evaluate_closure_readiness(results)
        self.assertEqual(decision.blocked_by, ("audit_chain", "frozen_inputs"))

    def test_the_decision_is_repeatable(self) -> None:
        first = evaluate_closure_readiness(self._all_pass())
        second = evaluate_closure_readiness(self._all_pass())
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------------------
# 9. 비밀값·개인정보·절대 경로 (AC-010)
# ---------------------------------------------------------------------------------------


class SecretAndPathHygieneTests(unittest.TestCase):
    """일곱 신규 파일 어디에도 자격증명·절대 경로·계정명이 없어야 한다."""

    def test_no_plaintext_credential_material_in_any_created_file(self) -> None:
        for relative in CREATED_PATHS:
            with self.subTest(path=relative):
                self.assertEqual(scan_for_plaintext_secrets(_read_text(relative)), [])

    def test_no_absolute_host_path_hostname_or_account_name(self) -> None:
        for relative in CREATED_PATHS:
            text = _read_text(relative)
            for pattern in ABSOLUTE_PATH_PATTERNS:
                with self.subTest(path=relative, pattern=pattern):
                    self.assertIsNone(re.search(pattern, text))

    def test_the_absolute_path_detector_is_not_vacuous(self) -> None:
        # 표본을 조각에서 조립한다. 완성된 절대 경로 문자열을 이 파일에 그대로 적으면 바로
        # 위의 위생 검사가 이 파일에서 그것을 찾아내고, 검사가 자기 자신에게 걸린다.
        separator = chr(92)
        samples = (
            "C:" + separator + "Users" + separator + "someone",
            separator * 2 + "build-host" + separator + "share",
            "/" + "home" + "/someone/checkout/",
            "/" + "tmp" + "/" + STALE_WORKSPACE_PREFIX + "abcd/",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(re.search(pattern, sample) for pattern in ABSOLUTE_PATH_PATTERNS),
                    f"탐지기가 {sample!r} 를 놓친다",
                )


# ---------------------------------------------------------------------------------------
# 10. 결정론 (AC-015)
# ---------------------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    """이 모듈이 표준 라이브러리만 쓰고 네트워크·프로세스·난수·고정 대기를 쓰지 않는지."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = ast.parse(_read_text(SUITE_PATH))

    def _imported_names(self) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add(f"{'.' * node.level}{node.module or ''}")
        return names

    def test_no_forbidden_module_is_imported(self) -> None:
        imported = self._imported_names()
        self.assertEqual(imported & FORBIDDEN_IMPORTS, set())

    def test_every_import_is_stdlib_or_a_declared_repository_module(self) -> None:
        allowed_stdlib = {
            "__future__",
            "ast",
            "dataclasses",
            "hashlib",
            "json",
            "pathlib",
            "re",
            "sys",
            "typing",
            "unittest",
        }
        allowed_repo = {
            "scripts.validate_baseline",
            "studio_core.collaboration",
            "studio_core.integrity",
            "studio_core.rng",
        }
        self.assertEqual(self._imported_names() - allowed_stdlib - allowed_repo, set())

    def test_no_sleep_process_or_random_call_appears(self) -> None:
        forbidden_calls = {"sleep", "system", "popen", "run", "check_call", "urlopen", "seed"}
        found: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in forbidden_calls:
                    found.append(name)
        self.assertEqual(found, [])

    def test_repeated_reads_produce_identical_evidence(self) -> None:
        """같은 입력에 대해 두 번 계산한 결과가 같아야 한다."""

        first = [hash_file(ROOT / relative, label=relative) for relative in CREATED_PATHS]
        second = [hash_file(ROOT / relative, label=relative) for relative in CREATED_PATHS]
        self.assertEqual(first, second)

    def test_the_module_creates_no_temporary_workspace(self) -> None:
        """임시 작업 공간을 만들지 않으므로 회수할 것도 없다. AST로 확인한다.

        원문 문자열 검색이 아니라 AST를 보는 이유는, 금지 이름을 문자열로 적는 순간 검사가
        자기 자신에게 걸리기 때문이다.
        """

        creators = {"mkdtemp", "mkstemp", "TemporaryDirectory", "NamedTemporaryFile", "mkdir"}
        called: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in creators:
                    called.append(name)
        self.assertEqual(called, [])
        self.assertNotIn("temp" + "file", self._imported_names())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
