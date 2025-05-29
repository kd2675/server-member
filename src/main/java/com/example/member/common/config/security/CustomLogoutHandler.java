package com.example.member.common.config.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            // 세션 무효화
            // securityLogoutHandler 부분에 세션 초기화가 있지만 그래도 명시적으로 다시 한번 사용한다.
            request.getSession().invalidate();

            // 쿠키 삭제 (예: JSESSIONID)
            Cookie cookie = new Cookie("AUTH_SESSION_ID", null);
                cookie.setMaxAge(0);
                cookie.setPath("/");

            response.addCookie(cookie);

            System.out.println("사용자가 로그아웃했습니다: " + authentication.getName());
        }
    }
}