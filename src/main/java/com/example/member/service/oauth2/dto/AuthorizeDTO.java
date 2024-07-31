package com.example.member.service.oauth2.dto;

import lombok.Data;

@Data
public class AuthorizeDTO {
    private String responseType;
    private String clientId;
    private String state;
    private String redirectUrl;
}
