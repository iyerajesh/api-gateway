package com.xylia.platform.gateway.api.exception;

import java.security.GeneralSecurityException;

public class APIGatewaySecurityException extends GeneralSecurityException {

    public APIGatewaySecurityException(String message, Throwable cause) {
        super(message, cause);
    }


}
