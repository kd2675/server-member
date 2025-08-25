# 👥 Server-Member
Second 프로젝트의 회원 관리 및 인증 서비스.
사용자 등록, 로그인, JWT 토큰 관리, Redis 기반 세션 관리 등 모든 인증/인가 기능을 담당하는 핵심 서비스.

## 📖 프로젝트 개요
Server-Member는 Spring Boot 기반의 회원 관리 및 인증 서비스.
JWT 토큰 기반 인증, Redis를 통한 Refresh Token 관리, 사용자 프로필 관리,
권한 관리 등의 기능을 제공하며, Second 프로젝트의 모든 인증 요청을 처리.

## 🎯 주요 기능
- **회원 관리**: 사용자 등록, 프로필 관리, 회원 정보 수정
- **JWT 인증**: Access Token/Refresh Token 기반 인증 시스템
- **Redis 세션**: Refresh Token Redis 저장 및 관리
- **권한 관리**: 역할 기반 접근 제어 (RBAC)
- **소셜 로그인**: 외부 OAuth 연동 (Google, Kakao, Naver 등)
- **보안 관리**: 비밀번호 암호화, 계정 보안 정책
- **사용자 해석**: Custom UserEntityResolver를 통한 사용자 컨텍스트 관리
- **토큰 갱신**: Refresh Token을 통한 무중단 토큰 갱신

## 🛠️ 기술 스택
- **Spring Boot 3.2.4**: 메인 애플리케이션 프레임워크
- **Spring Security**: 보안 및 인증/인가 처리
- **Spring Data JPA**: 회원 데이터 영속성 관리
- **Spring Data Redis**: Redis 기반 토큰 저장소
- **Spring Web**: RESTful API 서비스

### 인증 & 보안
- **JWT (JSON Web Token)**: 토큰 기반 인증
- **BCrypt**: 비밀번호 해시 암호화
- **Spring Security OAuth2**: 소셜 로그인 연동
- **CORS**: Cross-Origin 리소스 공유 설정

### 데이터베이스 & 캐시
- **MySQL**: 회원 정보 영구 저장소
- **Redis**: Refresh Token 및 세션 캐시
- **HikariCP**: 데이터베이스 커넥션 풀

### 토큰 생명주기
- **Access Token**: 1시간 (짧은 생명주기)
- **Refresh Token**: 2주 (긴 생명주기, Redis 저장)

### 인증 흐름
1. 사용자 로그인 요청
2. 인증 정보 검증
3. Access Token + Refresh Token 발급
4. Refresh Token → Redis 저장
5. 클라이언트에 토큰 응답
6. API 요청 시 Access Token 검증
7. 만료 시 Refresh Token으로 갱신
