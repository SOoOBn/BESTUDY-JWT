package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // 내 서버가 응답할 때 json을 자바스크립트에서 처리할 수 있도록 설정
        config.setAllowCredentials(true);
        // 모든 ip에 응답 허용
        config.addAllowedOrigin("*");
        // 모든 header에 응답 허용
        config.addAllowedHeader("*");
        // 모든 post, get, put, delete, patch 요청을 허용
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
