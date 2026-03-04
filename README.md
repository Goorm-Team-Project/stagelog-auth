# Auth Service (Lambda)

AWS API Gateway 앞단 인증 중앙화를 위한 Auth Service 뼈대입니다.

## 포함된 엔드포인트

- `GET /health`
- `GET /.well-known/jwks.json`
- `POST /auth/login` (stub)
- `POST /auth/refresh` (stub)

## 디렉토리

- `src/app.py`: API Gateway 라우터 진입점
- `src/handlers/`: 엔드포인트 핸들러
- `src/services/token_service.py`: JWT 발급/검증 공통
- `src/utils/`: 응답/요청/설정 유틸
- `events/`: 로컬 테스트 이벤트 샘플

## 로컬 실행

```bash
cd services/auth-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Lambda 핸들러는 `src.app.lambda_handler` 입니다.

## 환경변수

`.env.example` 참고:

- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `JWT_ALGORITHM` (기본: `HS256`)
- `JWT_ACCESS_TTL_SECONDS`
- `JWT_REFRESH_TTL_SECONDS`
- `JWT_SECRET_KEY` (HS256 사용 시 필수)
- `JWT_PUBLIC_JWK` (JWKS 응답용, JSON 문자열)

## 다음 작업

1. `login`에서 실제 소셜 로그인/OAuth 코드 교환 연결
2. `refresh`에서 refresh token 저장소(RDS/Redis) 검증 추가
3. API Gateway와 통합 배포(SAM/CDK/Terraform)
