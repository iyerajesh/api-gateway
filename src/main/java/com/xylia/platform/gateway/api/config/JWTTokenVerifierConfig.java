package com.xylia.platform.gateway.api.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.xylia.platform.gateway.api.exception.APIGatewaySecurityException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

@Component
@Slf4j
public class JWTTokenVerifierConfig {

    @Bean
    public JWTVerifier create(@Value("${jwt.key}") String publicKey)
            throws APIGatewaySecurityException {

        PublicKey pubKey;

        try {
            byte[] publicBytes = Base64.decodeBase64(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            pubKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            log.error("Could not load the public key! {}", ex.getMessage());
            throw new APIGatewaySecurityException("Could not load the public key!", ex);
        }

        return JWT.require(Algorithm.RSA256((RSAPublicKey) pubKey, null))
                .build();
    }
}