package com.xylia.platform.gateway.api.controller;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.SocketUtils;

import java.time.Duration;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.*;

@RunWith(SpringRunner.class)
@SpringBootTest(
        webEnvironment = RANDOM_PORT, properties = "management.server.port=${test.port}"
)
public class GenericFallbackControllerTest {

    public static final String ACTUATOR_HEALTH = "/actuator/health";
    public static final String ACTUATOR_INFO = "/actuator/info";
    public static final String GENERIC_FALLBACK = "/fallback/generic";

    private static final String LOCALHOST = "http://localhost";
    protected static int managementPort;

    @LocalServerPort
    protected int port = 0;

    protected WebTestClient webTestClient;
    protected String baseUri;

    @BeforeClass
    public static void beforeClass() {
        managementPort = SocketUtils.findAvailableTcpPort();
        System.setProperty("test.port", String.valueOf(managementPort));
    }

    @AfterClass
    public static void afterClass() {
        System.clearProperty("test.port");
    }

    @Before
    public void setUp() throws Exception {
        baseUri = LOCALHOST + ":" + port;
        this.webTestClient = WebTestClient.bindToServer()
                .responseTimeout(Duration.ofSeconds(10))
                .baseUrl(baseUri)
                .build();
    }

    @Test
    public void testIfGenericFallbackUrlWorks() {
        webTestClient.get().uri(GENERIC_FALLBACK).exchange().expectStatus().isOk();
    }

    @Test
    public void testIfHealthEndpointIsWorking() {
        webTestClient.get().uri(LOCALHOST + ":" + managementPort + ACTUATOR_HEALTH)
                .exchange()
                .expectStatus()
                .isOk();
    }

    @Test
    public void testIfActuatorInfoEndpointIsReturningStartupDate() {
        webTestClient.get().uri(LOCALHOST + ":" + managementPort + ACTUATOR_INFO)
                .exchange()
                .expectBody().jsonPath("$.context.startup-date")
                .isNotEmpty();
    }


}