# R0 자동 검증 보고서

- 실행일: `2026-08-28`
- 기준선 버전: `1.1.0`
- 결과: `PASS`
- 사람 승인: `APPROVED (2026-08-31)`
- 단위 테스트: `28 PASS`

## 통과 항목

1. 필수 기준선 파일과 Constitution 정책 문구 확인
2. 상시 에이전트 ID 9종의 정확성·중복 없음 확인
3. Registry와 개별 정의의 ID·slug·role·department 일치 확인
4. 모든 에이전트의 운영 직접 접근 금지와 handoff 참조 확인
5. Agent, Task, Handoff, Artifact 스키마의 로컬 참조 확인
6. 세 계약 예제의 스키마 적합성 확인
7. task·project·agent·artifact의 교차 참조 무결성 확인
8. `production_schedule_policy: prohibited_before_r5` 확인
9. 9개 부서 허브·하위방·권한·상태 전이와 완료 게이트 확인
10. 승인 지식 스키마·수명주기·검색 필터·자동 승격 금지 확인
11. Provider 요청·응답 스키마, 공급자 상태, 기능별 라우팅 확인
12. 상시 에이전트 9종에 Eval Set 9개와 18개 평가 사례 연결 확인
13. 유럽식 단일 제로 룰렛 37개 포켓·지급표·12개 고정 벡터 확인
14. 보안·비용·감사·위험 정책 확인

## 부정 테스트

- 필수 `goal`이 없는 Task는 거부됨
- 미승인 추가 필드가 있는 Task는 거부됨
- 올바르지 않은 SHA-256이 있는 Artifact는 거부됨
- 인계 확인이 비활성화된 Handoff는 거부됨
- 소유자가 아닌 에이전트의 작업 시작과 QA 우회 완료는 거부됨
- 승인되지 않은 지식과 권한을 초과한 지식 검색은 거부됨
- 예산 초과·제한정보·미설정 Provider 호출은 거부됨
- 룰렛 0의 외부 베팅 지급, 잘못된 결과 번호, 잘못된 비밀 참조는 거부됨

## 실행 명령

```bash
python scripts/validate_baseline.py
python -m unittest discover -s tests -v
```

본 자동 검증은 승인 근거이며 최종 승인 기록은 `approvals/SYS-010-R0-approval.yaml`이다.
