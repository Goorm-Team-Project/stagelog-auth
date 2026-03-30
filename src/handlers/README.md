핸들러 구성:

- `health.py`: liveness
- `jwks.py`: 공개키 노출
- `login.py`: 로그인/토큰 발급 (현재 bootstrap stub)
- `refresh.py`: refresh 토큰 검증 후 access 재발급
- `authorizer.py`: HTTP API Lambda Authorizer
