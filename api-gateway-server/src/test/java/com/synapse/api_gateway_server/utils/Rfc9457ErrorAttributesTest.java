package com.synapse.api_gateway_server.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;

import com.synapse.api_gateway_server.exception.ExceptionType;
import com.synapse.api_gateway_server.exception.InvalidTokenException;
import com.synapse.api_gateway_server.exception.RateLimitExceededException;

class Rfc9457ErrorAttributesTest {

    private final Rfc9457ErrorAttributes errorAttributes = new Rfc9457ErrorAttributes();
    private final HandlerStrategies handlerStrategies = HandlerStrategies.withDefaults();

    @Test
    void rateLimitExceptionDetailPopulatesResponse() {
        RateLimitExceededException exception = new RateLimitExceededException(ExceptionType.RATE_LIMIT_EXCEEDED);

        Map<String, Object> attributes = renderAttributes(exception, "/rate-limit");

        assertEquals(ExceptionType.RATE_LIMIT_EXCEEDED.getTitle(), attributes.get("detail"));
        assertEquals(ExceptionType.RATE_LIMIT_EXCEEDED.getCode(), attributes.get("code"));
    }

    @Test
    void authenticationExceptionKeepsCustomMessage() {
        String customDetail = "JWT token expired";
        InvalidTokenException exception = new InvalidTokenException(customDetail);

        Map<String, Object> attributes = renderAttributes(exception, "/auth");

        assertEquals(customDetail, attributes.get("detail"));
        assertEquals(ExceptionType.UNAUTHENTICATED.getCode(), attributes.get("code"));
    }

    @Test
    void jwtInvalidSignatureMapsToConfiguredCode() {
        InvalidTokenException exception = new InvalidTokenException("JWT signature invalid", ExceptionType.JWT_INVALID_SIGNATURE);

        Map<String, Object> attributes = renderAttributes(exception, "/auth");

        assertEquals(ExceptionType.JWT_INVALID_SIGNATURE.getCode(), attributes.get("code"));
        assertEquals(ExceptionType.JWT_INVALID_SIGNATURE.getTitle(), attributes.get("title"));
    }

    private Map<String, Object> renderAttributes(Throwable throwable, String path) {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());
        errorAttributes.storeErrorInformation(throwable, exchange);
        ServerRequest request = ServerRequest.create(exchange, handlerStrategies.messageReaders());
        return errorAttributes.getErrorAttributes(request, ErrorAttributeOptions.defaults());
    }
}
