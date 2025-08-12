package com.example.member.service.auth.database.rep.redis.user;

import org.example.database.database.auth.redis.UserRedisEntity;
import org.springframework.data.keyvalue.repository.KeyValueRepository;


public interface UserRedisREP extends KeyValueRepository<UserRedisEntity, String> {
}
