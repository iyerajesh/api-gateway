package com.xylia.platform.gateway.api.filter;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.xylia.platform.gateway.api.config.JwtTokenUtil.extractJWTToken;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@Order(0)
@Slf4j
public class JwtTokenFilter implements GlobalFilter, Ordered {

    private static final String X_JWT_SUBJECT = "x-jwt-subject";
    private JWTVerifier jwtVerifier;

    public JwtTokenFilter(JWTVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        try {

            String token = extractJWTToken(exchange.getRequest());
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            ServerHttpRequest mutatedRequest;

            if (decodedJWT != null && decodedJWT.getSubject() != null)
                mutatedRequest = exchange.getRequest().mutate()
                        .header(X_JWT_SUBJECT, decodedJWT.getSubject())
                        .build();
            else
                mutatedRequest = exchange.getRequest().mutate().header(X_JWT_SUBJECT, "NA")
                        .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } catch (JWTVerificationException ex) {
            log.error("Error while verifying token!: {}", ex);
            return this.onError(exchange, ex.getMessage());

        }
    }

    @Override
    public int getOrder() {
        return 0;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String error) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(UNAUTHORIZED);
        response.getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, formatAuthenticationMessage(error));

        return response.setComplete();
    }

    private String formatAuthenticationMessage(String error) {
        return String.format("Bearer realm=\"xylia.com\", " +
                "error=\"https://tools.ietf.org/html/rfc7519\", " +
                "error_description=\"%s\" ", error);
    }
}
