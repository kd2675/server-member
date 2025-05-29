package com.example.member.common.config.security;

import com.example.member.common.config.jwt.biz.CustomUserDetailsService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * UserDetailsService로 DB에서 읽어온 유저 정보 검증
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 사용자가 입력한 username, password
        String username = authentication.getName();
        String rawPassword = authentication.getCredentials().toString();

        // DB에서 유저 정보 조회
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);


        // 비밀번호(암호화) 검증
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        // 인증 성공 -> 최종 Authentication 객체
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,  // 보안을 위해 null 처리하거나 userDetails.getPassword()를 넣을 수 있음
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // Username/Password 방식만 처리
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
