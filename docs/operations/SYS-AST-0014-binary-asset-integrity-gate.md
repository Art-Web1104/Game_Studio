# SYS-AST-0014 저장소 바이너리 자산 무결성 게이트

- 작업: `SYS-AST-0014`
- 소유 에이전트: `A-02`
- 위험 등급: `MEDIUM`
- 정책 버전: `BINARY-ASSETS-001/1.0.0`
- 상태: 구현 완료, Artifact Contract·Handoff Packet 제출, 독립 검증 대기

## 1. 이 게이트가 대체한 결함

`tests/test_integrity.py`는 `report['files']['binary'] == 0`을 하드코딩하고 있었다. 이 단정은
무결성 속성이 아니다.

- 통과하는 이유가 "바이너리가 실제로 검증되었다"가 아니라 "아직 아트가 없다"이다.
- READY 작업 산출물과 Artifact Contract, 원시 바이트 SHA-256까지 완전히 추적되는 **정당한**
  최초 PNG가 들어오는 순간 검증이 실패한다.
- 그렇다고 단정만 삭제하면 어떤 바이너리든 무제한으로 들어온다. 바이너리는 리뷰어가 diff에서
  읽을 수 없는 유일한 산출물이므로, 개수 단정 삭제는 가장 위험한 완화다.

그래서 개수를 **불변식**으로 바꿨다. 아래 7개 조건을 모두 만족하는 바이너리만 통과하고,
그 밖의 모든 경우는 거부한다.

## 2. 불변식

| # | 조건 | 거부 코드 |
|---|------|-----------|
| 1 | 허용 루트 + 허용 확장자 (`policies/binary-assets.yaml`) | `ASSET_NOT_ALLOWLISTED` |
| 2 | 해당 확장자가 `.gitattributes`에서 `binary` 또는 `-text`로 고정 | `EXTENSION_NOT_PINNED_BINARY` |
| 3 | 상대 경로이며 심볼릭 링크·`..`·절대 경로·루트 이탈이 아님 (**파일을 열기 전에** 판정) | `ASSET_SYMLINK`, `ASSET_PATH_ESCAPE`, `ASSET_PATH_ABSOLUTE`, `ASSET_PATH_BACKSLASH`, `ASSET_PATH_NOT_NORMALISED` |
| 4 | Git LFS 포인터가 자산 자리에 치환되지 않음 | `ASSET_LFS_POINTER` |
| 5 | `studio_core.secret_scan` 규칙에 걸리는 바이트열이 없음 | `ASSET_CREDENTIAL_LIKE` |
| 6 | status가 `READY` 이후인 Task Contract의 deliverable로 참조됨 | `ASSET_UNTRACKED_BY_TASK` |
| 7 | Artifact primary/component 해시 또는 자산 매니페스트에 원시 바이트 SHA-256으로 선언되고 실제 값과 일치 | `ASSET_HASH_UNDECLARED`, `ASSET_HASH_MALFORMED`, `ASSET_HASH_MISMATCH`, `ASSET_SIZE_MISMATCH` |

매니페스트 자체의 문제는 `MANIFEST_SCHEMA_INVALID`, `MANIFEST_SCHEMA_MISSING`,
`MANIFEST_FILENAME_MISMATCH`, `MANIFEST_TARGET_MISSING`, `MANIFEST_UNREADABLE`로 거부한다.

**바이너리가 하나도 없으면 통과한다.** 빈 결과는 실패가 아니라, 게이트가 승인할 것도 거부할
것도 없다는 뜻이며 도입 시점 저장소의 정확한 상태다.

## 3. 초기 허용 목록

```yaml
allowlist:
  roots: [assets]
  extensions: [.png, .webp]
```

`assets/**/*.png`와 `assets/**/*.webp`만 허용한다. 오디오·폰트·3D 등 다른 확장자의 허용
시점과 절차는 A-30과 사용자가 실제 자산 수요가 생길 때 별도 승인 작업으로 결정한다.
`.gitattributes`에는 이보다 많은 확장자가 `binary`로 고정되어 있지만, 그 목록은 게이트를
넓히지 않는다. 게이트는 정책 허용 목록만 본다.

## 4. 해시 규약 — 텍스트 경로와 분리된 이유

| 대상 | 정규 표현 | 구현 |
|------|-----------|------|
| 텍스트 | UTF-8, `CRLF` → `LF` (단독 `CR`은 보존) | `studio_core.integrity.content_hash` |
| 바이너리 자산 | 원시 바이트 그대로 | `studio_core.binary_assets.raw_content_hash` |

바이너리 자산은 `studio_core.integrity.content_hash`를 **쓰지 않는다**. 그 함수는 텍스트에
대해 `CRLF`를 `LF`로 접는데, PNG에 그 경로를 태우면 `\r\n`을 포함한 원본과 `\n`으로 손상된
변형이 같은 해시를 갖게 된다. `raw_content_hash`는 바이트를 건드리지 않는다.

`studio_core/integrity.py`는 이 작업에서 **변경하지 않았다**. LF/CRLF 동치성, 단독 CR 보존,
스니프 창 밖 NUL 처리, 모호 인코딩 거부, git blob 일치, 변조 거부 동작은 전부 그대로다.

## 5. 자산 매니페스트

- 위치: `assets/manifests/{task_id}-assets.json`
- 스키마: `contracts/asset-manifest.schema.json`
- `hash_algorithm`은 `sha256-raw-bytes` 상수로 고정되어 있어, 매니페스트가 텍스트 정규화된
  해시를 주장할 수 없다.
- `path`, `content_hash`, `byte_size`, `media_type`, `source`, `rights`가 모두 필수다.
  `content_hash`가 빠진 항목은 스키마 위반이므로 통과가 아니라 거부다.
- `path` 패턴은 선행 구분자·드라이브 문자·역슬래시를 표현할 수 없고, 게이트는 그와 별개로
  `..`·절대 경로·심볼릭 링크를 파일을 열기 전에 다시 거부한다(다층 방어).

현재 저장소에는 매니페스트가 없다. 첫 아트 자산 작업이 자신의 매니페스트를 함께 제출한다.

## 6. 첫 자산을 넣는 절차

1. 자산을 넣을 작업의 Task Contract를 `READY` 이상으로 두고, deliverable의 `target_uri`에
   `repo://assets/...`를 명시한다.
2. `assets/manifests/{task_id}-assets.json`을 작성한다. `content_hash`는 원시 바이트
   SHA-256이다.

   ```bash
   python -c "from studio_core.binary_assets import raw_hash_file; print(raw_hash_file('assets/roulette/table.png'))"
   ```

3. Artifact Contract를 제출한다. 자산이 primary 산출물이면 `uri` + `content_hash`로,
   부속 자산이면 `specification`에 `<name>` (경로) 와 `<name>_hash` (해시) 쌍으로 선언한다.
4. 확장자가 정책 허용 목록에 없다면 먼저 승인 작업으로 목록을 넓히고, 같은 커밋에서
   `.gitattributes`에도 `binary`로 고정한다.
5. 두 검증 명령을 실행한다.

## 7. 검증 명령

```bash
python scripts/validate_baseline.py
python -m unittest discover -s tests -v
```

집중 검증:

```bash
python -m unittest tests.test_binary_assets tests.test_integrity -v
python -c "from scripts.validate_baseline import validate_content_integrity as v; print(v()['binary_assets'])"
```

## 8. 이 작업이 건드리지 않은 것

- `providers/registry.yaml`, `providers/routing-policy.yaml`의 라우트
- `apps/roulette_web/**`, `games/roulette/**`의 규칙·RNG·정산 코드
- `studio_core/integrity.py`의 텍스트 정규화 경로
- 저장소 바이너리 목록 — 이 작업은 아트·바이너리 자산을 **하나도 추가하지 않는다**.
  네거티브 픽스처는 전부 `tempfile.TemporaryDirectory()` 안에서 런타임에 생성되고 테스트가
  끝나면 사라진다.

## 9. 롤백

`policies/binary-assets.yaml`, `contracts/asset-manifest.schema.json`,
`studio_core/binary_assets.py`, `tests/test_binary_assets.py`, 이 문서,
`audit/events/SYS-AST-0014-events.json`, `artifacts/SYS-AST-0014-artifact.json`,
`handoffs/SYS-AST-0014-handoff.json`을 삭제하고,
`scripts/validate_baseline.py`, `tests/test_integrity.py`, `.gitattributes`를 직전 커밋
상태로 되돌린다. 세 파일의 원본 해시는 `tasks/SYS-AST-0014.json`의 `inputs`에 기록되어 있다.
바이너리를 추가하지 않았고 커밋·푸시도 하지 않았으므로 작업 트리 복원만으로 완전 복구된다.

## 10. 미확정 결정

- PNG/WebP 이외 확장자(오디오·폰트·3D)의 허용 시점과 승인 절차
- 작업별 매니페스트를 유지할지 단일 저장소 매니페스트로 통합할지 (Phase B 설계 검토)
- 대용량 자산의 Git LFS 도입 여부 (현재는 포인터 출현을 치환 공격 신호로 취급)
- R5 이전이므로 상용 제작 일정과 출시일은 확정하지 않는다.
