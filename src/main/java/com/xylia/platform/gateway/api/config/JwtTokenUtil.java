package com.xylia.platform.gateway.api.config;

import com.xylia.platform.gateway.api.exception.JWTTokenExtractException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@Slf4j
public class JwtTokenUtil {

    private static final String BEARER = "Bearer";

    public static String extractJWTToken(ServerHttpRequest request) {

        if (!request.getHeaders().containsKey(AUTHORIZATION))
            throw new JWTTokenExtractException("Authorization header is missing!");

        String authHeader = request.getHeaders().getFirst(AUTHORIZATION);
        log.info("Authorization header: {}", authHeader);

        if (StringUtils.isEmpty(authHeader))
            throw new JWTTokenExtractException("Authorization header is missing!");

        String[] components = authHeader.split("\\s");

        if (components.length != 2)
            throw new JWTTokenExtractException("Malformed Authorization content!");

        if (!BEARER.equals(components[0]))
            throw new JWTTokenExtractException("Bearer is needed!");

        return components[1].trim();
    }
}
