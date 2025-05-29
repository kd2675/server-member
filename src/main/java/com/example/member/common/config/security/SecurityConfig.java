package com.example.member.common.config.security;


import com.example.member.common.config.jwt.biz.CustomUserDetailsService;
import com.example.member.service.auth.database.rep.jpa.user.UserREP;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * CustomUserDetailsService (MyBatis UserMapper 사용)
     */
    @Bean
    public CustomUserDetailsService customUserDetailsService(UserREP userREP) {
        return new CustomUserDetailsService(userREP);
    }

    /**
     * CustomAuthenticationProvider
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(CustomUserDetailsService customUserDetailsService,BCryptPasswordEncoder passwordEncoder) {
        return new CustomAuthenticationProvider(customUserDetailsService, passwordEncoder);
    }

    /**
     * AuthenticationManager(ProviderManager)
     */
    @Bean
    public AuthenticationManager authenticationManager(CustomAuthenticationProvider provider) {
        return new ProviderManager(Collections.singletonList(provider));
    }

    /**
     * rememberMeService(UserDetailsService)
     */
    @Bean
    public RememberMeServices rememberMeServices(CustomUserDetailsService userDetailsService) {
        TokenBasedRememberMeServices rememberMeServices =
                new TokenBasedRememberMeServices("mySecretKey", userDetailsService);
        rememberMeServices.setTokenValiditySeconds(14 * 24 * 60 * 60); // 14일 유지
        rememberMeServices.setAlwaysRemember(true);
        return rememberMeServices;
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        // 커스텀 필터를 사용하면, SecurityContext 저장 및 관리 기능이 기본적으로 포함되지 않음. 그래서 별도의 처리가 필요하다.
        return  new DelegatingSecurityContextRepository(
                new HttpSessionSecurityContextRepository(),
                new RequestAttributeSecurityContextRepository()
        );
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthenticationManager authenticationManager,
                                           SecurityContextRepository securityContextRepository,
                                           RememberMeServices rememberMeServices,
                                           CustomLogoutHandler customLogoutHandler,
                                           CustomLogoutSuccessHandler customLogoutSuccessHandler) throws Exception {

        JsonUsernamePasswordAuthenticationFilter jsonAuthFilter = new JsonUsernamePasswordAuthenticationFilter(authenticationManager, rememberMeServices, securityContextRepository);
        jsonAuthFilter.setAuthenticationSuccessHandler(new JsonLoginSuccessHandler());

        http.csrf(AbstractHttpConfigurer::disable) // 예제용 CSRF 비활성
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers( "/login", "/signup", "/error", "/pass/*").permitAll();  // /login 은 누구나
                    auth.anyRequest().authenticated();           // 나머지는 인증 필요
                })
                .addFilterBefore(jsonAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> {
                    logout.logoutUrl("/logout")
                            .addLogoutHandler(customLogoutHandler)
                            .logoutSuccessHandler(customLogoutSuccessHandler);
                })
                .httpBasic(Customizer.withDefaults());

        // ✅ Remember-Me 설정 추가 (쿠키 기반)
        http.rememberMe(rememberMe -> rememberMe
                .rememberMeServices(rememberMeServices)
        );


        return http.build();
    }




}
