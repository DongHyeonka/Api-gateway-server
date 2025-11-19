package com.synapse.api_gateway_server.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.synapse.api_gateway_server.exception.ExceptionType;
import com.synapse.api_gateway_server.exception.InvalidTokenException;
import com.synapse.synapse_domain_model.SubscriptionTier;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class AuthenticationGatewayFilterFactoryTest {

    private static final String ISSUER = "synapse-auth";
    private static final String AUDIENCE = "api-gateway";
    private static final String SECRET = "super-secret";

    private final AuthenticationGatewayFilterFactory factory = new AuthenticationGatewayFilterFactory();

    @Test
    void validTokenSetsAuthenticatedUserAttribute() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        String token = buildToken(Instant.now().minusSeconds(5), Instant.now().plusSeconds(60));

        MockServerHttpRequest request = MockServerHttpRequest.get("/chat")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        StubGatewayFilterChain chain = new StubGatewayFilterChain();

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertTrue(chain.invoked());
        AuthenticatedUser user = exchange.getAttribute(AuthenticationGatewayFilterFactory.AUTHENTICATED_USER_ATTR);
        assertEquals("user-123", user.userId());
        assertEquals("workspace-456", user.workspaceId());
        assertEquals(SubscriptionTier.PRO, user.tier());

        assertEquals("user-123", chain.lastExchange().getRequest().getHeaders().getFirst(AuthenticationGatewayFilterFactory.HEADER_USER_ID));
        assertEquals("workspace-456", chain.lastExchange().getRequest().getHeaders().getFirst(AuthenticationGatewayFilterFactory.HEADER_WORKSPACE_ID));
        assertEquals(SubscriptionTier.PRO.name(), chain.lastExchange().getRequest().getHeaders().getFirst(AuthenticationGatewayFilterFactory.HEADER_TIER));
    }

    @Test
    void missingAuthorizationHeaderThrowsInvalidToken() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/chat").build());
        StubGatewayFilterChain chain = new StubGatewayFilterChain();

        expectInvalidToken(filter.filter(exchange, chain), ExceptionType.UNAUTHENTICATED);
    }

    @Test
    void preservesRequestIdHeaderWhenPresent() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        String token = buildToken(Instant.now().minusSeconds(5), Instant.now().plusSeconds(60));

        MockServerHttpRequest request = MockServerHttpRequest.get("/chat")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .header(AuthenticationGatewayFilterFactory.HEADER_REQUEST_ID, "req-123")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StubGatewayFilterChain chain = new StubGatewayFilterChain();
        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals("req-123", chain.lastExchange().getRequest().getHeaders().getFirst(AuthenticationGatewayFilterFactory.HEADER_REQUEST_ID));
    }

    @Test
    void expiredTokenFailsVerification() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        String token = buildToken(Instant.now().minusSeconds(3600), Instant.now().minusSeconds(360));
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/chat").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).build()
        );

        expectInvalidToken(filter.filter(exchange, new StubGatewayFilterChain()), ExceptionType.JWT_TOKEN_EXPIRED);
    }

    @Test
    void invalidBearerPrefixReturnsInvalidHeader() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        String token = buildToken(Instant.now().minusSeconds(5), Instant.now().plusSeconds(60));
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/chat").header(HttpHeaders.AUTHORIZATION, "Basic " + token).build()
        );

        expectInvalidToken(filter.filter(exchange, new StubGatewayFilterChain()), ExceptionType.INVALID_AUTHORIZATION_HEADER);
    }

    @Test
    void invalidSignatureReturnsSpecificType() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        Algorithm otherAlgorithm = Algorithm.HMAC256("another-secret");
        String token = JWT.create()
            .withIssuer(ISSUER)
            .withAudience(AUDIENCE)
            .withSubject("user-123")
            .withClaim("workspace_id", "workspace-456")
            .withClaim("tier", SubscriptionTier.PRO.name())
            .withIssuedAt(Date.from(Instant.now().minusSeconds(5)))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
            .sign(otherAlgorithm);

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/chat").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).build()
        );

        expectInvalidToken(filter.filter(exchange, new StubGatewayFilterChain()), ExceptionType.JWT_INVALID_SIGNATURE);
    }

    @Test
    void missingWorkspaceClaimReturnsInvalidClaim() {
        AuthenticationGatewayFilterFactory.Config config = baseConfig();
        GatewayFilter filter = factory.apply(config);

        Algorithm algorithm = Algorithm.HMAC256(SECRET);
        String token = JWT.create()
            .withIssuer(ISSUER)
            .withAudience(AUDIENCE)
            .withSubject("user-123")
            .withClaim("tier", SubscriptionTier.PRO.name())
            .withIssuedAt(Date.from(Instant.now().minusSeconds(5)))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
            .sign(algorithm);

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/chat").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).build()
        );

        expectInvalidToken(filter.filter(exchange, new StubGatewayFilterChain()), ExceptionType.JWT_INVALID_CLAIM);
    }

    private AuthenticationGatewayFilterFactory.Config baseConfig() {
        AuthenticationGatewayFilterFactory.Config config = new AuthenticationGatewayFilterFactory.Config();
        config.setIssuer(ISSUER);
        config.setAudiences(List.of(AUDIENCE));
        config.setHmacSecret(SECRET);
        config.setClockSkewSeconds(60);
        return config;
    }

    private String buildToken(Instant issuedAt, Instant expiresAt) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET);
        return JWT.create()
            .withIssuer(ISSUER)
            .withAudience(AUDIENCE)
            .withSubject("user-123")
            .withClaim("workspace_id", "workspace-456")
            .withClaim("tier", SubscriptionTier.PRO.name())
            .withIssuedAt(Date.from(issuedAt))
            .withNotBefore(Date.from(issuedAt.minusSeconds(5)))
            .withExpiresAt(Date.from(expiresAt))
            .sign(algorithm);
    }

    private void expectInvalidToken(Mono<Void> result, ExceptionType expectedType) {
        StepVerifier.create(result)
            .expectErrorSatisfies(error -> {
                assertTrue(error instanceof InvalidTokenException);
                InvalidTokenException invalid = (InvalidTokenException) error;
                assertEquals(expectedType, invalid.getErrorCode());
            })
            .verify();
    }

    private static class StubGatewayFilterChain implements GatewayFilterChain {
        private boolean invoked;
        private ServerWebExchange lastExchange;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            invoked = true;
            lastExchange = exchange;
            return Mono.empty();
        }

        boolean invoked() {
            return invoked;
        }

        ServerWebExchange lastExchange() {
            return lastExchange;
        }
    }
}
