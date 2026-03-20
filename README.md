# Auth Service (Lambda)

AWS API Gateway 앞단에서 인증을 중앙화하는 Lambda 기반 Auth Service입니다.

## 엔드포인트

- `POST /api/auth/login/{provider}`
  - `provider`: `kakao | google | naver`
  - OAuth 인가 코드 교환 후 로그인 처리
- `POST /api/auth/signup`
  - `register_token`, `nickname`, `email` 기반 회원가입 완료
- `POST /api/auth/refresh`
  - 쿠키의 `refresh_token`으로 access token 재발급
- `GET /api/auth/keep`
  - access token 기반 로그인 유지 정보 조회
- `POST /api/auth/logout`
  - refresh 세션 폐기 + access token 블랙리스트 등록
- `GET /health`
- `GET /.well-known/jwks.json`

참고: `POST /api/auth/login` (bootstrap 테스트 경로)는 제거됨.

## 핵심 구조

- 라우팅: `src/app.py`
  - `/api` prefix 정규화 후 핸들러로 라우팅
- 핸들러: `src/handlers/`
  - 비즈니스 흐름 진입점
- 서비스: `src/services/`
  - JWT, DB, Redis, 세션 저장소 로직
- 유틸: `src/utils/`
  - 공통 응답/요청 파싱/설정 로더

## 기능-함수 매핑

- 소셜 로그인(OAuth 코드 교환)
  - `src/handlers/login.py`
  - `handle_social_login(event, provider)`
  - `_exchange_oauth_code(...)`
  - `_fetch_provider_id(...)`

- 가입 필요(202 + register_token)
  - `src/handlers/login.py`
  - `handle_social_login(...)`
  - `src/services/token_service.py`
  - `issue_register_token(...)`

- 로그인 성공(200 + access_token + refresh cookie)
  - `src/handlers/login.py`
  - `handle_social_login(...)`
  - `src/services/token_service.py`
  - `issue_access_token(...)`, `issue_refresh_token(...)`
  - `src/services/session_store.py`
  - `store_refresh_session(...)`

- Refresh 재발급
  - `src/handlers/refresh.py`
  - `handle_refresh(event)`
  - `_get_refresh_token(event)` (cookie 전용)
  - `src/services/token_service.py`
  - `verify_refresh_token(...)`, `issue_access_token(...)`
  - `src/services/session_store.py`
  - `is_refresh_session_active(...)`

- Keep(유저 정보 유지)
  - `src/handlers/refresh.py`
  - `handle_keep(event)`
  - `src/services/auth_repository.py`
  - `get_user_for_keep(...)`, `get_bookmark_event_ids(...)`

- Logout
  - `src/handlers/refresh.py`
  - `handle_logout(event)`
  - `src/services/session_store.py`
  - `revoke_refresh_session(...)`
  - `blacklist_access_token(...)`

- API Gateway Lambda Authorizer
  - `src/handlers/authorizer.py`
  - `lambda_handler(event, context)`
  - `src/services/session_store.py`
  - `is_access_token_blacklisted(...)`

## 세션 저장 전략 (Hybrid)

- Refresh token
  - 영속 저장: RDS (`refresh_tokens`)
  - 고속 조회: Redis key + TTL
- Access token 즉시 무효화
  - 로그아웃 시 Redis 블랙리스트 등록
  - Authorizer가 블랙리스트 조회 후 차단

## 응답 계약

모든 API body는 monolith `common_response`와 동일한 payload 구조를 유지:

- `success`
- `message`
- `data`

Lambda 환경이므로 HTTP 상태코드는 `statusCode`로 반환.

## 로컬 테스트

```bash
cd /home/woosupar/stagelog-auth
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

## 환경변수

`.env.example` 참고.

- JWT: `JWT_*`
- SSM cold-start config: `AUTH_SSM_PREFIXES`
- DB: `DB_*`
- Redis: `REDIS_*`
- OAuth: `KAKAO_*`, `GOOGLE_*`, `NAVER_*`

## 배포/인프라 연동

- Lambda + API Gateway는 `stagelog-infra/1-permanent` Terraform에서 관리
- Lambda 아티팩트는 S3 기반(`auth_lambda_s3_bucket`, `auth_lambda_s3_key`, `authorizer_lambda_s3_key`)
- GitHub Actions 워크플로 파일은 존재하며 현재 실행 비활성화 상태
