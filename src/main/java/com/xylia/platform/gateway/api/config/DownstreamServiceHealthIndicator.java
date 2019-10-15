package com.xylia.platform.gateway.api.config;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class DownstreamServiceHealthIndicator implements ReactiveHealthIndicator {

    private Mono<Health> checkDownStreamServiceHealth() {
        return Mono.just(new Health.Builder().up().build());
    }

    @Override
    public Mono<Health> health() {
        return checkDownStreamServiceHealth().onErrorResume(ex -> Mono.just(new Health.Builder().up().build()));
    }
}
