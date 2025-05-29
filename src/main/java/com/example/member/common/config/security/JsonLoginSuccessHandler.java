package com.example.member.common.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JsonLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, String> responseData = new HashMap<>();
            responseData.put("message", "Login successful!");
            responseData.put("redirectUrl", "/me"); // ✅ 클라이언트에서 리디렉트 처리 가능

        response.getWriter().write(objectMapper.writeValueAsString(responseData));
    }
}