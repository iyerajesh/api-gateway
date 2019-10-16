package com.xylia.platform.gateway.api.filter;

import com.auth0.jwt.JWTVerifier;
import com.netflix.loadbalancer.Server;
import com.xylia.platform.gateway.api.exception.JWTTokenExtractException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import static com.xylia.platform.gateway.api.filter.JwtTokenFilter.X_JWT_SUBJECT;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RunWith(MockitoJUnitRunner.class)
public class JwtTokenFilterTest {

    public static final String FAKEENDPOINT = "https://endpoint";
    public static final String TOKEN = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDatDQ+zxw4qZfAOUroVWApUfLFUaGPP4eIEO20LyotqDIr0OBkVs1GGG8X3GgD4g+woQWRpm8nDE/qsLmmhhLHi/BgwyYuNGPEPdgcDBpyaLPtM6Cr933zjVC/M4nDiNqcq8EXMvF+y7b3AJmUG/Se9O9gLW4eVhhNqp4QbEd1uwIDAQAB";
    public static final String BEARER = "Bearer ";

    private ServerWebExchange exchange;
    private JwtTokenFilter jwtTokenFilter;

    @Mock
    private JWTVerifier jwtVerifier;

    @Mock
    private GatewayFilterChain chain;

    @Before
    public void setUp() throws Exception {
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get(FAKEENDPOINT).build());
        jwtTokenFilter = new JwtTokenFilter(jwtVerifier);
    }

    @Test
    public void shouldReturnUnauthorizedIfNoAuthHeaderFoundInRequest() {

        URI uri = UriComponentsBuilder.fromUriString(FAKEENDPOINT).build().toUri();
        exchange.getAttributes().put(GATEWAY_REQUEST_URL_ATTR, uri);
        jwtTokenFilter.filter(exchange, chain);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(UNAUTHORIZED);
        verifyNoMoreInteractions(chain);
    }

    @Test
    public void shouldReturnUnauthorizedIfBearerTokenValueIsEmpty() throws UnknownHostException {
        ServerWebExchange exchangeWihToken = createMockTokenRequest("");
        assertThat(exchangeWihToken.getResponse().getStatusCode()).isEqualTo(UNAUTHORIZED);
    }

    @Test
    public void shouldReturnUnauthorizedIfBearerTokenIsInvalid() throws UnknownHostException {
        ServerWebExchange exchangeWithToken = createMockTokenRequest(BEARER);
        assertThat(exchangeWithToken.getResponse().getStatusCode()).isEqualTo(UNAUTHORIZED);
    }

    @Test
    public void shouldPassSecurityTokenCheck() throws UnknownHostException {
        ServerWebExchange exchangeWithToken = createMockTokenRequest(BEARER + TOKEN);
        assertThat(exchangeWithToken.getResponse().getStatusCode()).isNull();
    }

    private ServerWebExchange createMockTokenRequest(String authHeader) throws UnknownHostException {
        MockServerHttpRequest request = MockServerHttpRequest
                .get(FAKEENDPOINT)
                .remoteAddress(new InetSocketAddress(InetAddress.getByName("10.0.0.1"), 80))
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .build();

        ServerWebExchange exchangeWithToken = MockServerWebExchange.from(request);
        jwtTokenFilter.filter(exchangeWithToken, chain);

        return exchangeWithToken;
    }

    @After
    public void tearDown() throws Exception {
    }
}