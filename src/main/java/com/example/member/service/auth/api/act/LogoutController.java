package com.example.member.service.auth.api.act;

import com.example.member.common.config.jwt.provider.JwtTokenProvider;
import com.example.member.service.auth.api.biz.LogoutService;
import com.example.member.service.auth.api.dto.TokenDTO;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.core.response.base.dto.ResponseDTO;
import org.example.core.response.base.vo.Code;
import org.example.core.utils.CookieUtils;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(value = {"/member"})
public class LogoutController {
    private final LogoutService logoutService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/logout")
    public ResponseDTO logout(
            @RequestHeader("Authorization") String accessToken,
            @CookieValue("RefreshToken") String refreshToken
    ) {
        if (!StringUtils.isEmpty(accessToken) && !StringUtils.isEmpty(refreshToken)) {
            CookieUtils.deleteCookie("RefreshToken");
            String userEmail = jwtTokenProvider.getUserEmail(jwtTokenProvider.resolveToken(accessToken));
            logoutService.logout(userEmail, TokenDTO.of(accessToken, refreshToken));

            return ResponseDTO.of(true, Code.OK);
        } else {
            return ResponseDTO.of(true, Code.BAD_REQUEST);
        }
    }
}
