package com.example.member.service.auth.database.rep.redis.authorization;

import org.springframework.data.keyvalue.repository.KeyValueRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsedAuthorizationCodeRedisREP extends KeyValueRepository<UsedAuthorizationCodeRedis, String> {
}