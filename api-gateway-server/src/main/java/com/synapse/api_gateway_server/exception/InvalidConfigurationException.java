package com.synapse.api_gateway_server.exception;

public class InvalidConfigurationException extends AbstractGatewayException {
    public InvalidConfigurationException(ExceptionType exceptionType) {
        super(exceptionType);
    }

    public InvalidConfigurationException(String detail, ExceptionType exceptionType) {
        super(detail, exceptionType);
    }

    public InvalidConfigurationException(String detail) {
        super(detail, ExceptionType.INVALID_INPUT_VALUE);
    }
}
