package com.synapse.api_gateway_server.filter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.synapse.api_gateway_server.exception.ExceptionType;
import com.synapse.api_gateway_server.exception.InvalidConfigurationException;
import com.synapse.api_gateway_server.exception.InvalidTokenException;
import com.synapse.synapse_domain_model.SubscriptionTier;

import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Mono;

public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    public static final String AUTHENTICATED_USER_ATTR = "authenticatedUser";
    static final String HEADER_USER_ID = "X-User-Id";
    static final String HEADER_WORKSPACE_ID = "X-Workspace-Id";
    static final String HEADER_TIER = "X-Subscription-Tier";
    static final String HEADER_REQUEST_ID = "X-Request-Id";

    public AuthenticationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        Config validatedConfig = config.withDefaults();
        Algorithm algorithm = resolveAlgorithm(validatedConfig);
        JWTVerifier verifier = buildVerifier(validatedConfig, algorithm);

        return (exchange, chain) -> Mono.defer(() -> authenticate(exchange, chain, validatedConfig, verifier));
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, GatewayFilterChain chain, Config config, JWTVerifier verifier) {
        String token = extractBearerToken(exchange.getRequest());
        DecodedJWT jwt;
        try {
            jwt = verifier.verify(token);
        } catch (TokenExpiredException ex) {
            return Mono.error(new InvalidTokenException("JWT expired", ExceptionType.JWT_TOKEN_EXPIRED));
        } catch (SignatureVerificationException | AlgorithmMismatchException ex) {
            return Mono.error(new InvalidTokenException("JWT signature invalid", ExceptionType.JWT_INVALID_SIGNATURE));
        } catch (InvalidClaimException ex) {
            return Mono.error(new InvalidTokenException("JWT claim invalid: " + ex.getMessage(), ExceptionType.JWT_INVALID_CLAIM));
        } catch (JWTVerificationException ex) {
            return Mono.error(new InvalidTokenException("JWT verification failed: " + ex.getMessage(), ExceptionType.UNAUTHENTICATED));
        }

        validateIssuedAt(jwt, config.getClockSkewSeconds());
        ensureRequiredClaims(jwt, config.getRequiredClaims());

        AuthenticatedUser user = mapToUser(jwt);
        exchange.getAttributes().put(AUTHENTICATED_USER_ATTR, user);

        String requestId = exchange.getRequest().getHeaders().getFirst(HEADER_REQUEST_ID);

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
            .header(HEADER_USER_ID, user.userId())
            .header(HEADER_WORKSPACE_ID, user.workspaceId())
            .header(HEADER_TIER, user.tier().name());

        if (StringUtils.hasText(requestId)) {
            requestBuilder.header(HEADER_REQUEST_ID, requestId);
        }

        ServerHttpRequest mutatedRequest = requestBuilder.build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String extractBearerToken(ServerHttpRequest request) {
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authorization)) {
            throw new InvalidTokenException("Authorization header is missing", ExceptionType.UNAUTHENTICATED);
        }

        String value = authorization.trim();
        if (value.length() < 7) {
            throw new InvalidTokenException("Authorization header is malformed", ExceptionType.INVALID_AUTHORIZATION_HEADER);
        }

        String prefix = value.substring(0, 6).toLowerCase(Locale.ROOT);
        if (!"bearer".equals(prefix)) {
            throw new InvalidTokenException("Authorization header must start with Bearer", ExceptionType.INVALID_AUTHORIZATION_HEADER);
        }

        String token = value.substring(6).trim();
        if (!StringUtils.hasText(token)) {
            throw new InvalidTokenException("Bearer token is empty", ExceptionType.INVALID_AUTHORIZATION_HEADER);
        }

        return token;
    }

    private void validateIssuedAt(DecodedJWT jwt, long clockSkewSeconds) {
        if (jwt.getIssuedAt() == null) {
            throw new InvalidTokenException("JWT is missing the iat claim", ExceptionType.JWT_INVALID_CLAIM);
        }

        Instant issuedAt = jwt.getIssuedAt().toInstant();
        Instant now = Instant.now().plusSeconds(clockSkewSeconds);
        if (issuedAt.isAfter(now)) {
            throw new InvalidTokenException("JWT iat is in the future", ExceptionType.JWT_INVALID_CLAIM);
        }
    }

    private void ensureRequiredClaims(DecodedJWT jwt, List<String> requiredClaims) {
        for (String claim : new LinkedHashSet<>(requiredClaims)) {
            if ("sub".equals(claim)) {
                if (!StringUtils.hasText(jwt.getSubject())) {
                    throw new InvalidTokenException("JWT is missing the subject", ExceptionType.JWT_INVALID_CLAIM);
                }
                continue;
            }

            if (jwt.getClaim(claim).isMissing() || jwt.getClaim(claim).isNull()) {
                throw new InvalidTokenException("JWT is missing required claim: " + claim, ExceptionType.JWT_INVALID_CLAIM);
            }
        }
    }

    private AuthenticatedUser mapToUser(DecodedJWT jwt) {
        String userId = jwt.getSubject();
        String workspaceId = jwt.getClaim("workspace_id").asString();
        if (!StringUtils.hasText(workspaceId)) {
            throw new InvalidTokenException("JWT workspace_id claim is empty", ExceptionType.JWT_INVALID_CLAIM);
        }

        String tierClaim = jwt.getClaim("tier").asString();
        if (!StringUtils.hasText(tierClaim)) {
            throw new InvalidTokenException("JWT tier claim is empty", ExceptionType.JWT_INVALID_CLAIM);
        }

        SubscriptionTier tier;
        try {
            tier = SubscriptionTier.valueOf(tierClaim.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new InvalidTokenException("Unsupported subscription tier: " + tierClaim, ExceptionType.JWT_INVALID_CLAIM);
        }

        return new AuthenticatedUser(userId, workspaceId, tier);
    }

    private Algorithm resolveAlgorithm(Config config) {
        if (StringUtils.hasText(config.getHmacSecret())) {
            return Algorithm.HMAC256(config.getHmacSecret());
        }

        if (StringUtils.hasText(config.getRsaPublicKey())) {
            return Algorithm.RSA256(parsePublicKey(config.getRsaPublicKey()), null);
        }

        throw new InvalidConfigurationException("JWT signing configuration is missing", ExceptionType.INVALID_INPUT_VALUE);
    }

    private RSAPublicKey parsePublicKey(String pem) {
        try {
            String sanitized = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(sanitized);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new InvalidConfigurationException("Invalid RSA public key", ExceptionType.INVALID_INPUT_VALUE);
        }
    }

    private JWTVerifier buildVerifier(Config config, Algorithm algorithm) {
        var verification = JWT.require(algorithm);
        if (StringUtils.hasText(config.getIssuer())) {
            verification.withIssuer(config.getIssuer());
        }
        if (!config.getAudiences().isEmpty()) {
            verification.withAudience(config.getAudiences().toArray(new String[0]));
        }
        return verification.acceptLeeway(config.getClockSkewSeconds()).build();
    }

    @Getter
    @Setter
    public static class Config {
        private String issuer;
        private List<String> audiences = new ArrayList<>();
        private List<String> requiredClaims = new ArrayList<>(List.of("sub", "workspace_id", "tier"));
        private String hmacSecret;
        private String rsaPublicKey;
        private long clockSkewSeconds = 60;

        public Config withDefaults() {
            if (!StringUtils.hasText(issuer)) {
                throw new InvalidConfigurationException("JWT issuer must be configured", ExceptionType.INVALID_INPUT_VALUE);
            }
            if (!StringUtils.hasText(hmacSecret) && !StringUtils.hasText(rsaPublicKey)) {
                throw new InvalidConfigurationException("Provide either an HMAC secret or RSA public key", ExceptionType.INVALID_INPUT_VALUE);
            }

            if (requiredClaims == null || requiredClaims.isEmpty()) {
                requiredClaims = new ArrayList<>(List.of("sub", "workspace_id", "tier"));
            }
            if (audiences == null) {
                audiences = new ArrayList<>();
            }

            return this;
        }

        public List<String> getAudiences() {
            return Collections.unmodifiableList(audiences);
        }

        public void setAudiences(List<String> audiences) {
            this.audiences = audiences == null ? new ArrayList<>() : new ArrayList<>(audiences);
        }

        public List<String> getRequiredClaims() {
            return Collections.unmodifiableList(requiredClaims);
        }

        public void setRequiredClaims(List<String> requiredClaims) {
            this.requiredClaims = (requiredClaims == null || requiredClaims.isEmpty())
                ? new ArrayList<>(List.of("sub", "workspace_id", "tier"))
                : new ArrayList<>(requiredClaims);
        }
    }
}
