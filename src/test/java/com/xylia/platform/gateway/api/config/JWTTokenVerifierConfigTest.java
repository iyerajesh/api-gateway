package com.xylia.platform.gateway.api.config;

import com.xylia.platform.gateway.api.exception.APIGatewaySecurityException;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTTokenVerifierConfigTest {

    private JWTTokenVerifierConfig jwtTokenVerifierConfig;
    private static final String INVALID_PUBLIC_KEY = "Invalid Public Key";
    private static final String VALID_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDatDQ+zxw4qZfAOUroVWApUfLFUaGPP4eIEO20LyotqDIr0OBkVs1GGG8X3GgD4g+woQWRpm8nDE/qsLmmhhLHi/BgwyYuNGPEPdgcDBpyaLPtM6Cr933zjVC/M4nDiNqcq8EXMvF+y7b3AJmUG/Se9O9gLW4eVhhNqp4QbEd1uwIDAQAB";

    @Before
    public void setUp() throws Exception {
        jwtTokenVerifierConfig = new JWTTokenVerifierConfig();
    }

    @Test(expected = APIGatewaySecurityException.class)
    public void verifyJWTVerifierKeyWithInvalidKey() throws APIGatewaySecurityException {
        jwtTokenVerifierConfig.create(INVALID_PUBLIC_KEY);
    }

    @Test
    public void verifyJWTVerifierKeyWithValidKey() throws APIGatewaySecurityException {
        jwtTokenVerifierConfig.create(VALID_PUBLIC_KEY);
        assertThat(jwtTokenVerifierConfig).isNotNull();
    }
}