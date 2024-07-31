package com.example.member.service.auth.database.rep.redis.authorization;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;


@Getter
@RedisHash("usedAuthorizationCode")
@AllArgsConstructor
@Builder
public class UsedAuthorizationCodeRedis {
    @Id
    private String id;

    private String userEmail;

    @TimeToLive
    private Long expiration;

    public static UsedAuthorizationCodeRedis of(String authorizationCode, String userEmail, Long remainingMilliSeconds) {
        return UsedAuthorizationCodeRedis.builder()
                .id(authorizationCode)
                .userEmail(userEmail)
                .expiration(remainingMilliSeconds / 1000)
                .build();
    }
}
