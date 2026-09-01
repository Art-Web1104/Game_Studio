# SYS-CI-0012: 지속 검증 CI와 저장소 비밀값 스캔

- Task Contract: `tasks/SYS-CI-0012.json` (owner `A-02`, risk `MEDIUM`)
- Workflow: `.github/workflows/ci.yml`
- Scanner: `studio_core/secret_scan.py` (엔진) + `scripts/scan_secrets.py` (CLI)
- 독립성: PR #2 및 R2 작업 흐름과 의존 관계가 없다. `workflow_run`, `workflow_call`, `needs`를
  사용하지 않으므로 다른 브랜치·워크플로가 없어도 단독 실행된다.

## 언제 도는가

| 트리거 | 범위 |
| --- | --- |
| `pull_request` | 모든 Pull Request |
| `push` | `main` 브랜치만 |

동일 ref의 이전 실행은 `concurrency.cancel-in-progress`로 취소된다.

## 무엇을 검사하는가

| Job | 검사 | 제한시간 |
| --- | --- | --- |
| `baseline` (Python 3.11, 3.12) | `python scripts/validate_baseline.py`, `python -m unittest discover -s tests -v`, `python -m compileall -q studio_core scripts tests` | 15분 |
| `secret-scan` (Python 3.12) | `python scripts/scan_secrets.py` | 10분 |

매트릭스는 `pyproject.toml`의 `requires-python >= 3.11` 하한과 로컬 사용 버전 두 개로만 유지한다.

## 보안 자세

- `permissions: contents: read`를 워크플로와 모든 Job에 명시한다. 쓰기 스코프는 없다.
- `actions/checkout`은 `persist-credentials: false`로 실행해 러너의 `.git/config`에 토큰을 남기지 않는다.
- `secrets` 컨텍스트와 `GITHUB_TOKEN`을 어떤 스텝도 참조하지 않는다. 이 워크플로에는 구성해야 할
  저장소 비밀값이 없다.
- 사용하는 액션은 GitHub 공식 `actions/checkout`, `actions/setup-python` 두 종뿐이다.
- 설치 의존성은 `pyproject.toml`이 선언한 `PyYAML>=6,<7` 하나뿐이다.

## 비밀값 스캐너

`studio_core/secret_scan.py`는 규칙 기반 결정론적 스캐너다. 엔트로피 추정이나 시각 의존 값이
없으므로 같은 트리는 항상 같은 결과를 낸다.

- **규칙**: `RULES`의 `SecretRule(rule_id, description, pattern)` 항목. 규칙 추가는 튜플 한 줄과
  `tests/test_secret_scan.py::POSITIVE_SAMPLES` 한 줄이면 끝난다.
- **제외**: `ScanConfig` 한 곳에 모여 있다. 무시 디렉터리(`.git`, `__pycache__`, `.venv`,
  `node_modules`, `dist`, `build` 등), 무시 경로 접두사(`.claude/worktrees/`), 생성물 확장자
  (`.pyc`, `.png`, `.min.js`, `.lock`, `.map` 등), NUL 바이트 또는 UTF-8 디코딩 실패로 판정한
  이진 파일, 5MiB 초과 파일.
- **비노출**: 탐지 결과는 `rule_id`, 경로, 행, 열과 함께 원문을 `<redacted:...>`로 치환한
  발췌만 담는다. 비밀값이 CI 로그로 옮겨가지 않는다.
- **정렬**: 파일 순회와 탐지 결과 모두 상대 POSIX 경로 기준으로 정렬한다.

### 오탐을 다루는 방법

1. 우선 값을 저장소 밖으로 옮긴다. 자격 증명은 `policies/security.yaml`과
   `operations/collaboration.yaml`에 따라 `secret-ref://` 참조로만 남긴다.
2. 실제 자격 증명이 아닌 문서·픽스처 예시라면 같은 줄 또는 바로 윗줄에 인라인 마커를 단다.

   ```text
   aws_access_key_id = AKIA...  # secret-scan: allow -- AWS 문서 예시
   ```

   마커는 해당 줄과 바로 다음 줄만 면제한다. 파일 전체를 가리지 않으므로 이후 실수는 계속 잡힌다.
3. 파일 단위 면제가 불가피하면 `--allow-path <상대경로>`를 쓴다. 이 방식은 그 파일의 미래 변경까지
   가리므로 검토 기록을 남긴 경우에만 사용한다. 기본 허용목록은 비어 있다.

의도적으로 커밋된 예시는 `tests/fixtures/secret_scan/allowlisted-sample.txt`에 모아 두었고,
마커 덕분에 저장소 전체 스캔을 실패시키지 않는다. `tests/test_secret_scan.py`는 마커를 제거하면
같은 줄이 다시 탐지되는지까지 확인한다.

### 종료 코드

| 코드 | 의미 |
| --- | --- |
| `0` | 탐지 없음 |
| `1` | 하나 이상 탐지, CI 실패 |
| `2` | 스캔 자체 실패(잘못된 루트, 읽기 불가) |

## 로컬에서 CI와 동일하게 돌리기

```bash
python scripts/validate_baseline.py
python -m unittest discover -s tests -v
python -m compileall -q studio_core scripts tests
python scripts/scan_secrets.py
```

## 롤백

`.github/workflows/ci.yml`을 삭제하면 CI는 즉시 중단된다. 스캐너·테스트·문서와
`scripts/validate_baseline.py`의 필수 파일 목록 추가분을 함께 되돌리면 SYS-CI-0012 이전 상태로
완전히 복구된다. GitHub 측 설정 변경은 없다.

## 남은 승인 항목

- 필수 상태 검사(branch protection) 지정은 저장소 관리 권한이 필요하므로 사용자 승인 사항이다.
- 공식 액션은 워크플로의 검증된 40자 커밋 SHA로 이미 고정되어 있다. 버전 갱신 시 워크플로와 tests/test_secret_scan.py의 APPROVED_ACTION_PINS를 함께 변경한다.
- 호스티드 GitHub Actions 실행 결과는 원격 푸시 승인 이후에만 관측할 수 있으므로 현재 상태는
  `NOT_RUN`이다.
