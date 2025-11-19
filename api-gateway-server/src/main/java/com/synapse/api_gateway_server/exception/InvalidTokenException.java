package com.synapse.api_gateway_server.exception;

public class InvalidTokenException extends AbstractGatewayException {
    public InvalidTokenException(String detail) {
        super(detail, ExceptionType.UNAUTHENTICATED);
    }

    public InvalidTokenException(String detail, ExceptionType exceptionType) {
        super(detail, exceptionType);
    }

    public InvalidTokenException(ExceptionType exceptionType) {
        super(exceptionType);
    }
}
