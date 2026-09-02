# R4 유닛 2: 룰렛 테이블 분위기 배경과 심리스 펠트 텍스처 아트 디렉션 브리프

- 작업: `R4-ART-0007`
- 위험 등급: `MEDIUM`
- 소유자: `A-02` (실행 책임) / 아트 리드 승인자: `A-30`
- 상태: **후보 자산 제출됨. `USER` 시각 검토와 아트 방향 사인오프 승인 기록됨(2026-09-02).
  `A-30` 아트 디렉션 승인과 `A-50` 독립 검토 미발행, 권리 판정 미결, 최종 게이트 미발행**
- 산출물: `assets/roulette/table-atmosphere-background.webp`,
  `assets/roulette/felt-tile.png`, `assets/manifests/R4-ART-0007-assets.json`,
  `docs/art/R4-ART-0007-generation-record.json`, 이 문서
- 정식 게이트 매니페스트: `assets/manifests/R4-ART-0007-assets.json`
  (`contracts/asset-manifest.schema.json` 준수, `SYS-AST-0014` 바이너리 자산 무결성 게이트가
  읽는 경로·원시 바이트 SHA-256·바이트 크기·출처·권리 선언)
- 상세 생성 기록: `docs/art/R4-ART-0007-generation-record.json` (프롬프트 원문, 공급자와 라우트,
  기계적 후처리 이력, 원본 렌더 해시, 픽셀 측정값, 통합 제약, 미결 승인 항목)

**내부 프로토타입 자산입니다. 가상 칩만 사용하며 현금 가치가 없습니다.**

이 문서는 아트 방향 기록이다. 게이트 판정도, 최종 자산 지정도, 통합 착수 허가도 아니다.
일정·기간·마감·출시일을 정하지 않으며 `R5` 승인 전에는 상용 제작 일정을 확정하지 않는다.

## 1. 이 유닛이 닫는 것과 닫지 않는 것

닫는 것: `R4-UI-0006`으로 병합된 플레이어블 슬라이스가 지금까지 손으로 쓴 CSS와 인라인 SVG로만
그려 온 화면에, 처음으로 회화적 배경 레이어로 쓸 수 있는 비트맵 두 장을 후보 상태로 만든다.
아트 방향, 프롬프트 원문, 생성 메타데이터, 기계적 후처리 이력, 측정값, 통합 제약을 남긴다.

닫지 않는 것: 애플리케이션 코드 통합, `ALLOWED_STATIC_SUFFIXES` 개정, CSS 배선, 자산의 실제
서빙. 그리고 **금지 내용 독립 판정(`AC-010`)과 톤 판정(`AC-011`)도 닫지 않는다.** `USER`의
시각 검토와 아트 방향 사인오프는 승인으로 기록되었지만, 그것이 이 두 독립 판정을 대신하지
않는다. 아래 5절과 6절이 그 경계를 기록한다.
`apps/roulette_web`, `studio_core`, `tests`, `scripts`, `games` 아래의 어떤 파일도 이 작업에서
바뀌지 않는다.

## 2. 스타일 기준

프리미엄 모던 스타일라이즈드 게임 테이블이다. 사진 실사풍 도박 광고가 아니다. 목표하는 인상은
조용하고 촉각적인 빈 테이블의 분위기이며, 화면의 주인공은 자산이 아니라 그 위에 얹히는 기존
UI다. 배경은 읽기를 방해하지 않는 배경으로만 존재해야 한다.

팔레트는 `apps/roulette_web/static/styles.css`의 기존 토큰을 벗어나지 않는다.

| 역할 | 토큰 | 값 |
| --- | --- | --- |
| 지배 | `--felt-900` | `#04140d` |
| 지배 | `--felt-800` | `#072318` |
| 지배 | `--felt-700` | `#0b3222` |
| 지배 | `--felt-600` | `#10462f` |
| 지배 | `--line` | `#1d5b3e` |
| 강조 | `--gold-dim` | `#8a7327` |
| 강조 | `--gold` | `#d4af37` |
| 강조 | `--gold-bright` | `#f2d98b` |
| 구조 | `--pocket-black` | `#14181b` |
| 강조 | `--pocket-red` | `#b3202c` |

금지: 사진 합성 질감, 렌즈 플레어와 보케를 앞세운 광고 조명, 네온, 밝은 골드, 화려한 당첨 연출,
부의 과시를 암시하는 소재. 그리고 문자·숫자·글리프·서명·워터마크, 로고와 상표, 사람과 신체
일부, 현금·동전·통화 기호, 결제나 환전을 연상시키는 도상, 미리 구워진 룰렛 결과나 포켓 색 배열,
배당과 지급 정보, 버튼이나 슬라이더 같은 UI 컨트롤 형상.

## 3. 프롬프트 원문

두 프롬프트를 파이프 구분 문자열 그대로 기록한다. 매니페스트의 `prompt_verbatim` 필드와 동일한
문자열이다.

### 3.1 배경

```
Use case: stylized-concept | Asset type: production candidate source for a 2560x1440 decorative roulette web-game background | Primary request: create an original premium modern stylized game-table atmosphere backdrop for an existing responsive UI overlay, with no gameplay information | Scene/backdrop: deep emerald felt table field, restrained matte graphite outer architecture, very subtle dark brass-gold edge trim, and tiny muted roulette-red edge accents | Subject: an elegant empty table atmosphere; keep the exact central 49% of image width and the central vertical mobile crop visually quiet, uniform, dark, and free of focal objects; decorative structure stays only in far outer gutters and corners | Style/medium: polished stylized 3D game environment background, sophisticated and tactile, not photorealistic gambling advertising | Composition/framing: true 16:9 wide landscape, near top-down perspective, symmetric balance, generous central negative space, safe for cover cropping to 9:16 and 21:9 | Lighting/mood: very low-key diffuse ambient glow, calm and premium, no bright hotspot, no lens flare; all visible highlights subdued enough for white UI text and translucent panels | Color palette: dominant deep emerald close to #04140d, #072318, #0b3222 and #10462f; matte graphite #14181b; restrained dark brass near #8a7327; tiny muted red near #b3202c; gold area below 8 percent and red below 4 percent | Materials/textures: fine woven felt, subtle brushed dark brass, matte graphite, soft shallow shadows | Constraints: absolutely no text, letters, numbers, glyphs, logos, trademarks, watermark, signatures, people, hands, cash, banknotes, coins, currency symbols, payment or cashout imagery, chips, cards, dice, alcohol, UI controls, buttons, sliders, roulette pockets, roulette numbers, roulette wheel focal point, baked game results, payout information, or readable signage; original design only; no device mockup, no frame mockup; central UI zone must remain empty and low contrast | Avoid: flashy casino advertising, neon, bright gold, clutter, literal betting scene, recognizable casino branding, dramatic winning effects, wealth imagery, photorealistic advertisement
```

### 3.2 펠트 타일

```
Use case: stylized-concept | Asset type: production candidate source for a 512x512 seamless CSS tile texture | Primary request: create an original subtle deep-emerald woven felt material texture that repeats perfectly in both directions beneath roulette UI panels | Scene/backdrop: flat orthographic edge-to-edge material sample only | Subject: extremely fine short felt fibers with restrained woven grain, uniform density, and gentle micro-variation | Style/medium: polished stylized game material texture with understated realistic material cues | Composition/framing: exact square, perfectly flat top-down, no perspective, no border, no center focal point, seamless continuation across left/right and top/bottom edges | Lighting/mood: neutral diffuse low-contrast illumination with no directional shadow, hotspot, gradient, or vignette | Color palette: dark emerald close to #04140d, #072318, #0b3222 and #10462f; no bright green and no crushed black areas | Materials/textures: fine felt fibers, subtle woven grain, soft matte finish; feature size below 2 percent of image width | Constraints: genuinely seamless and tileable across all four edges; local tonal variation restrained to approximately plus or minus 12 in 8-bit values; absolutely no text, letters, numbers, glyphs, logos, trademarks, watermark, signatures, people, hands, cash, banknotes, coins, currency symbols, payment imagery, chips, cards, dice, roulette pockets, roulette numbers, game results, payout information, UI controls, brass, frame, border, symbols, stains, seams, folds, spotlight, vignette, or large-scale motif; original design only | Avoid: obvious repeating pattern, grid, checkerboard, noisy high-contrast grain, bright fibers, directional lighting, recognizable objects, photorealistic casino scene
```

## 4. 후보 자산 사실 기록

두 파일 모두 이 작업에서 더 이상 처리하거나 수정하지 않는다. 아래 값은 저장소에 놓인 파일에서
직접 읽은 값이며 매니페스트 선언값과 동일하다.

### 4.1 `assets/roulette/table-atmosphere-background.webp`

| 항목 | 값 |
| --- | --- |
| 해상도 | 2560x1440 (16:9) |
| 포맷 | WEBP, RGB, 알파 없음, 불투명 |
| 프레임 | 1, 애니메이션 아님, 인터레이스 아님 |
| 바이트 크기 | 27,024 |
| SHA-256 | `sha256:e1211d1e3418b5fc77b454227ac2a9c93ea6df27a19f56123973e5246347ef27` |
| 원본 PNG SHA-256 | `sha256:ffa8d7688fea7e75dd54160d95a30f1c2bfea2a69f45f1971bc964316f4e43a5` |
| 최대 상대 휘도 | 0.236868665 |
| 평균 상대 휘도 | 0.004392710 |
| 중앙 대역 / 거터 엣지 비 | 0.142016618 |
| 추정 골드 면적 | 0.360867% |
| 추정 레드 면적 | 0.031603% |

중앙 대역은 이미지 폭의 가운데 49%로, 데스크톱 셸의 `max-width: 78rem` (1248px)에 대응한다.

기계적 후처리: 중앙 정렬 16:9 크롭 → 리샘플 → 밝기 조정 → 대비 조정 → WebP 인코딩. 회화적
재작업, 추가 이미지 합성, 문자·오버레이 삽입은 없다.

### 4.2 `assets/roulette/felt-tile.png`

| 항목 | 값 |
| --- | --- |
| 해상도 | 512x512 (1:1) |
| 포맷 | PNG-24, RGB, 알파 없음, 불투명 |
| 프레임 | 1, 애니메이션 아님, 인터레이스 아님 |
| 바이트 크기 | 79,412 |
| SHA-256 | `sha256:59208eb18461045d27b86d574d0cbe48fbbd0603a279dda48c02cb73b15b9dc7` |
| 원본 PNG SHA-256 | `sha256:f2c69e40619ff288b85c3b4ccce5aa0b227886ae396da3e70ad53655a6797bbd` |
| 이음매 비 | 0.0 |
| 저주파 편차 | 0.757519% |
| 16px 국소 휘도 표준편차 최대 | 1.9678 |
| 휘도 범위 | 18.32 ~ 32.04 |

기계적 후처리: 고주파 성분 추출 → 미러링된 주기 사분면 구성 → 절제된 블러 → 절제된 포스터화
→ RGB PNG 인코딩. 회화적 재작업, 추가 이미지 합성, 문자·오버레이 삽입은 없다.

### 4.3 바이너리 예산

저장소에 추가되는 바이너리 총합은 **106,436 바이트**다 (27,024 + 79,412).

## 5. 공급자와 출처

- 공급자: `codex_imagegen` (Codex Built-in ImageGen), 관리형 커넥터 경로.
- 라우트: `providers/routing-policy.yaml`의 `image` 라우트 (preferred `codex_imagegen`,
  fallbacks 없음). 대체 공급자는 사용하지 않았다.
- 활성화 근거: `providers/evidence/SYS-IMG-0013-codex-imagegen-connection-proof.yaml`.
- 생성 일자: 2026-09-02 (UTC).
- 모델 이름·버전: **unavailable**. 관리형 내장 경로가 노출하지 않으므로 매니페스트에 `null`로
  남긴다. 임의의 모델명이나 버전을 지어내지 않았다.
- 호출 비용: **unavailable**. 같은 이유로 `null`이다.
- 외부 참조 자료: **없음**. 공급자에 어떤 외부 레퍼런스 이미지도 제공하지 않았다.
- `SYS-IMG-0013` 프로브 이미지(PRB-001, PRB-002)는 이 자산의 후보나 원본으로 사용하지 않았다.
- PII 없음, 비밀정보 없음. 데이터 등급 `INTERNAL`.

권리 판정: **`PENDING_HUMAN_REVIEW`**. 권리 상태, 학습 허용 여부, 상용 사용 가능 여부 모두
미결이며 `A-30`이 판정 소유자다. `USER`의 아트 방향 사인오프는 **시각·아트 방향 수용에
한정된 승인**이며 권리·라이선스·학습 허용·상용 사용 판정으로 확대되지 않는다. 매니페스트의
`license`는 `PENDING-HUMAN-DETERMINATION`, `commercial_use`는 `false`,
`training_permission`은 `UNKNOWN`, `provenance_complete`는 `false`로 그대로 둔다.
자산 상태는 **후보(CANDIDATE) / 제출됨(SUBMITTED)**이고, `USER` 사인오프가 기록된 지금도
`A-30`의 아트 디렉션 승인과 `A-50`의 독립 검토가 기록되기 전까지 어떤 산출물도 확정 자산이
아니다.

## 6. 시각 검토 상태 — `USER` 시각 검토는 PASS, 독립 금지 내용 판정은 PENDING

기록해야 할 사실은 네 가지이고, 서로 섞지 않는다.

1. 공급자의 원본 출력물은 생성 시점에 화면에 표시되었고, 그 시점에 Codex가 관측한 금지 내용은
   없었다. 이는 원본 렌더에 한정된 제한적 관측이다.
2. **Codex의 view-image 헬퍼는 이 Windows 콘솔에서 실패했다.** 따라서 에이전트 측에서 처리본
   WebP와 PNG를 다시 표시하는 경로는 끝내 열리지 않았다. 이는 해소되지 않은 **도구 한계**로
   남으며, 그대로 기록한다.
3. **`USER`의 시각 검토는 성공했다.** 2026-09-02에 최종 처리본 이미지 두 장을 `USER`가 직접
   열어 확인했고, 이미지가 괜찮다고 판단해 아트 방향을 승인했다. 따라서 `USER` 시각 검토는
   **PASS**이고 `USER` 아트 방향 사인오프는 **APPROVED**로 기록한다.
4. **그 승인은 시각·아트 방향 수용까지다.** `AC-010`의 금지 내용 체크리스트는 `A-30`의 원본
   해상도·400% 확대 항목별 판정과 `A-50`의 독립 재판정으로만 닫히는 별개 판정이며, 아직
   수행되지 않았다. `AC-011`의 톤 판정도 같은 이유로 열려 있다.

4절의 측정값은 픽셀 통계일 뿐이며 `AC-010`과 `AC-011`을 대신하지 않는다. `USER` 사인오프도
이 두 독립 판정을 대신하지 않는다.

## 7. 통합 제약 (AC-013)

이 작업은 코드 통합을 포함하지 않는다. 아래는 후속 통합 유닛이 추측 없이 배선할 수 있도록
남기는 제약이며, `apps/roulette_web/server.py`의 현재 구현값과 대조해 기록했다.

- **배경 CSS 배치**: 기존 `body`의 `background-color: var(--felt-900)` 위에 얹는 레이어로
  선언한다. `background-size: cover`, 중앙 정렬 포지션을 권장한다. 배경은 `--felt-900`의
  대체가 아니다.
- **cover 동작**: 자산은 9:16, 16:9, 21:9 cover 크롭 모두에서 중앙 대역에 초점 오브젝트가
  남지 않도록 구성했다. 중앙 49% 대역이 UI 컬럼과 겹친다.
- **펠트 타일 `background-size`**: 512px 타일 크기에 해당하는 고정값(예:
  `background-size: 512px 512px`)을 권장한다.
- **반복 축**: `background-repeat: repeat`로 가로·세로 두 축 모두 반복한다.
- **폴백 유지**: `--felt-900` `#04140d`를 하위 `background-color`로 반드시 유지한다. 이미지
  로드가 실패해도 화면이 기존 모습으로 안전하게 퇴화해야 한다.
- **CSP**: `SECURITY_HEADERS`의 Content-Security-Policy는 이미
  `img-src 'self' data:`를 허용한다. 따라서 **동일 출처 서빙만 허용된다.** 원격 출처에서
  자산을 불러오는 배선은 정책상 차단된다.
- **확장자 허용 공백**: `ALLOWED_STATIC_SUFFIXES`는 현재
  `.html`, `.css`, `.js`, `.svg`, `.json`, `.webmanifest` 여섯 개뿐이다. `.webp`와 `.png`가
  **없다.** 지금 상태로 두 자산은 404로 응답된다. 후속 통합 유닛이 확장자 허용을 개정해야
  자산이 서빙된다. 그 개정은 이 작업의 소유가 아니다.

## 8. 사인오프 상태

### 8.1 닫힌 항목

- `USER` 최종 처리본 이미지 시각 검토 — **PASS** (2026-09-02)
- `USER` 아트 방향 사인오프 — **APPROVED** (2026-09-02)

### 8.2 남은 미결 항목

- `A-30` 아트 디렉션 승인
- `A-50` 독립 검토
- `A-30`·`A-50`의 처리본 검토(원본 해상도 및 400% 확대). `USER` 시각 검토 PASS가 이 독립
  검토를 대신하지 않는다.
- 금지 내용 체크리스트 독립 판정 (`AC-010`)
- 브리프 톤 기준 대비 판정 (`AC-011`)
- 권리·학습 허용 판정 (`AC-009`)
- 기존 표면 불투명도로 합성한 명암비 검증 (`AC-007`)
- 최종 게이트 판정 (`NOT_ISSUED`) 및 확정 자산 지정 (미발행)

`Artifact Contract`(`artifacts/R4-ART-0007-artifact.json`)와
`Handoff Packet`(`handoffs/R4-ART-0007-handoff.json`)은 제출되었다.

후속 통합 유닛의 착수 조건은 8.2의 항목이 모두 기록되는 것이다. `USER` 사인오프 하나만으로는
착수 조건이 충족되지 않는다.
