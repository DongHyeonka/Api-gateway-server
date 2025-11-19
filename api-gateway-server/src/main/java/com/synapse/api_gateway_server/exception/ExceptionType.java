package com.synapse.api_gateway_server.exception;

import org.springframework.http.HttpStatus;
import static org.springframework.http.HttpStatus.*;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ExceptionType {

    // Cxxx: Client / Config Errors
    INVALID_INPUT_VALUE("C001", "잘못된 입력 값 / Invalid Input", BAD_REQUEST),

    // Axxx: Authentication & Authorization
    INVALID_AUTHORIZATION_HEADER("A001", "잘못된 인증 헤더 / Invalid Authorization Header", BAD_REQUEST),
    UNAUTHENTICATED("A002", "인증되지 않음 / Unauthenticated", UNAUTHORIZED),
    JWT_TOKEN_EXPIRED("A003", "만료된 JWT 토큰 / JWT Token Expired", UNAUTHORIZED),
    ACCESS_DENIED("A004", "접근 거부 / Access Denied", FORBIDDEN),
    JWT_INVALID_SIGNATURE("A005", "잘못된 서명 / JWT Invalid Signature", UNAUTHORIZED),
    JWT_INVALID_CLAIM("A006", "잘못된 클레임 / JWT Invalid Claim", UNAUTHORIZED),

    // Gxxx: Gateway routing
    ROUTE_NOT_FOUND("G001", "라우트 없음 / Route Not Found", NOT_FOUND),

    // Pxxx: Policy configuration
    POLICY_NOT_FOUND("P001", "정책을 찾을 수 없음 / Policy Not Found", NOT_FOUND),

    // Rxxx: Rate limiting
    IP_RATE_LIMIT_EXCEEDED("R001", "IP 제한 초과 / IP Rate Limit Exceeded", TOO_MANY_REQUESTS),
    GLOBAL_RATE_LIMIT_EXCEEDED("R002", "글로벌 제한 초과 / Global Rate Limit Exceeded", TOO_MANY_REQUESTS),
    RATE_LIMIT_EXCEEDED("R003", "구독 제한 초과 / Subscription Rate Limit Exceeded", TOO_MANY_REQUESTS),
    TOTAL_LIMIT_EXCEEDED("R004", "총량 제한 초과 / Total Limit Exceeded", TOO_MANY_REQUESTS),

    // Sxxx: System / Infra
    INTERNAL_SERVER_ERRORS("S001", "내부 서버 오류 / Internal Server Error", INTERNAL_SERVER_ERROR),
    RATE_LIMIT_CHECK_FAILED("S002", "레이트리밋 검증 실패 / Rate Limit Check Failed", INTERNAL_SERVER_ERROR),
    SERVICE_UNAVAILABLES("S003", "서비스 일시 중단 / Service Temporarily Unavailable", SERVICE_UNAVAILABLE);
    
    private final String code;
    private final String title;
    private final HttpStatus status;
}
