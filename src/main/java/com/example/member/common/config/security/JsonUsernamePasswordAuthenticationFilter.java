package com.example.member.common.config.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

public class JsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    // /login 경로로 들어오는 POST 요청만 처리한다고 가정
    public JsonUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, RememberMeServices rememberMeService, SecurityContextRepository securityContextRepository) {
        super(new AntPathRequestMatcher("/login", "POST"));
        setAuthenticationManager(authenticationManager);
        setRememberMeServices(rememberMeService);

        // 커스텀 필터를 사용하면, SecurityContext 저장 및 관리 기능이 기본적으로 포함되지 않음. 그래서 별도의 처리가 필요하다.
        // 공통으로 등록된 bean을 사용하도록 함
        setSecurityContextRepository(securityContextRepository);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {

        // Request Body JSON 파싱
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        // Username/Password 토큰 생성
        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        // AuthenticationManager에게 인증 위임
        return getAuthenticationManager().authenticate(authRequest);
    }

/*    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            jakarta.servlet.FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        // ✅ RememberMeServices 호출하여 쿠키 저장
        //rememberMeServices.loginSuccess(request, response, authResult);
    }*/

    // 내부 DTO
    @Data
    private static class LoginRequest {
        private String username;
        private String password;

        @JsonProperty("remember-me")
        private boolean rememberMe;
    }
}
