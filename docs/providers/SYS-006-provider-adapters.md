# SYS-006 외부 AI Provider Adapter

상태: `INTERFACE_IMPLEMENTED / EXTERNAL_CREDENTIALS_NOT_CONFIGURED`

모든 외부 AI는 동일한 요청·응답 계약을 통과한다. 프로그래밍 공급자는 사용자 결정에 따라
Claude Code 하나로 단일화했다. 활성화 조건은 연결 설정,
요청 스키마, 정보등급, 최소 권한, 예산 예약, 출력 스키마, 권리·출처, 독립 검토이다.

현재 Codex 코드 경로는 비활성화되어 있으며 Claude·Layer AI·오디오·3D는 실제 연결과 자격
증명 설정 전까지 비활성 상태이다. Claude 미연결 시 다른 코드 모델로 우회하지 않고 작업을
차단한다. 저장소에는 비밀값이 없고 참조만 둔다.
