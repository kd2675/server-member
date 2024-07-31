package com.example.member.service.auth.api.biz;

import com.example.member.common.config.jwt.provider.JwtTokenProvider;
import com.example.member.service.auth.api.dto.LoginParamDTO;
import com.example.member.service.auth.api.dto.TokenDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {
    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;

    public TokenDTO login(LoginParamDTO loginParamDTO) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginParamDTO.getUserEmail());
        jwtTokenProvider.checkPassword(loginParamDTO.getUserPassword(), userDetails.getPassword());

        String accessToken = jwtTokenProvider.generateAccessToken(userDetails.getUsername());
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails.getUsername());

//        CookieUtils.createCookie("RefreshToken", JwtHeaderUtilEnums.GRANT_TYPE.getValue() + refreshTokenRedis.getRefreshToken());

        return TokenDTO.of(accessToken, refreshToken);
    }
}
