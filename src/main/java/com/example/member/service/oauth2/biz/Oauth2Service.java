package com.example.member.service.oauth2.biz;

import com.example.member.common.config.jwt.provider.JwtTokenProvider;
import com.example.member.service.auth.api.dto.LoginParamDTO;
import com.example.member.service.auth.api.dto.TokenDTO;
import com.example.member.service.auth.database.rep.jpa.user.UserREP;
import com.example.member.service.auth.database.rep.redis.authorization.UsedAuthorizationCodeRedis;
import com.example.member.service.auth.database.rep.redis.authorization.UsedAuthorizationCodeRedisREP;
import com.example.member.service.oauth2.dto.AuthorizationCodeDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.core.response.base.exception.GeneralException;
import org.example.core.response.base.vo.Code;
import org.example.database.database.auth.entity.UserEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class Oauth2Service {

    private final PasswordEncoder passwordEncoder;
    private final UserREP userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final UsedAuthorizationCodeRedisREP usedAuthorizationCodeRedisREP;

    public AuthorizationCodeDTO loginToAuthorizationCode(LoginParamDTO loginParamDTO) {
        UserEntity userEntity = userRepository.findByEmailWithRole(loginParamDTO.getUserEmail())
                .orElseThrow(() -> new GeneralException(Code.NO_SEARCH_USER, "회원이 없습니다."));
        checkPassword(loginParamDTO.getUserPassword(), userEntity.getPassword());

        String userEmail = userEntity.getEmail();
        String authorizationCode = jwtTokenProvider.generateAccessToken(userEmail);

        return AuthorizationCodeDTO.of(authorizationCode);
    }

    public TokenDTO authorizationCodeToken(String authorizationCode) {
        String resolveToken = jwtTokenProvider.resolveToken(authorizationCode);

        if (jwtTokenProvider.checkUsedAuthorizationCode(resolveToken)) {
            throw new GeneralException(Code.USED_AUTHORIZATION_CODE);
        }

        String userEmail = jwtTokenProvider.getUserEmail(resolveToken);
        long remainMilliSeconds = jwtTokenProvider.getRemainMilliSeconds(resolveToken);

        String accessToken = jwtTokenProvider.generateAccessToken(userEmail);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userEmail);

        usedAuthorizationCodeRedisREP.save(UsedAuthorizationCodeRedis.of(resolveToken, userEmail, remainMilliSeconds));

        return TokenDTO.of(accessToken, refreshToken);
    }

    private void checkPassword(String rawPassword, String findMemberPassword) {
        if (!passwordEncoder.matches(rawPassword, findMemberPassword)) {
            throw new GeneralException(Code.NOT_MATCH_PASSWORD, "비밀번호가 맞지 않습니다.");
        }
    }
}
