package com.example.member.service.oauth2.dto;

import com.example.auth.config.jwt.enums.JwtHeaderUtilEnums;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizationCodeDTO {

    private String grantType;
    private String authorizationCode;

    public static AuthorizationCodeDTO of(String authorizationCode) {
        return AuthorizationCodeDTO.builder()
                .grantType(JwtHeaderUtilEnums.GRANT_TYPE.getValue())
                .authorizationCode(authorizationCode)
                .build();
    }
}