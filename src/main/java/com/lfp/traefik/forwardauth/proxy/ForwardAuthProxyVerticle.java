package com.lfp.traefik.forwardauth.proxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lfp.traefik.forwardauth.proxy.jwt.JWTContext;
import com.lfp.traefik.forwardauth.proxy.jwt.TokenContext;
import io.fusionauth.jwt.domain.JWT;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.httpproxy.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import one.util.streamex.EntryStream;
import one.util.streamex.StreamEx;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.Failable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * A Verticle that handles forwarding authentication requests through an OAuth2 proxy
 * and normalizes the data received from an OIDC service. Roles and permissions are
 * checked, added as headers, and all claims are added as headers as well.
 */
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Getter
public class ForwardAuthProxyVerticle extends AbstractVerticle {
    private static final String AUTH_REQUEST_HEADER_NAME_PREFIX = "x-auth-request";
    private static final String ACCESS_TOKEN_HEADER_NAME = AUTH_REQUEST_HEADER_NAME_PREFIX + "-access-token";
    private static final String ID_TOKEN_HEADER_NAME = AUTH_REQUEST_HEADER_NAME_PREFIX + "-id-token";
    CompletableFuture<InetSocketAddress> startFuture = new CompletableFuture<>();
    ObjectMapper objectMapper;
    ForwardAuthProxyConfig config;

    /**
     * Starts the Verticle by creating an HTTP client, setting up a reverse proxy,
     * and initializing an HTTP server to handle requests.
     *
     * @throws Exception if an error occurs during startup.
     */
    @Override
    public void start() throws Exception {
        HttpClient httpClient = vertx.createHttpClient();
        HttpProxy proxy = HttpProxy.reverseProxy(httpClient);
        proxy.addInterceptor(createProxyInterceptor());
        String oauth2ProxyHost = config.getOauth2ProxyHost();
        proxy.origin(config.getOauth2ProxyPort(), oauth2ProxyHost);
        vertx.createHttpServer().requestHandler(proxy).exceptionHandler(failure -> {
            log.error("server error", failure);
        }).listen(config.getServerPort(), config.getServerHost()).toCompletionStage().whenCompleteAsync((httpServer, failure) -> {
            Optional.ofNullable(failure)
                    .ifPresentOrElse(startFuture::completeExceptionally,
                            () -> startFuture.complete(new InetSocketAddress(config.getServerHost(), httpServer.actualPort())));
        });
    }

    /**
     * Creates a ProxyInterceptor to handle proxy requests and responses.
     *
     * @return the ProxyInterceptor instance.
     */
    private ProxyInterceptor createProxyInterceptor() {
        return new ProxyInterceptor() {

            @Override
            public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
                return ProxyInterceptor.super.handleProxyRequest(context).onFailure(failure -> {
                    log.error("proxy request error", failure);
                });
            }

            @Override
            public Future<Void> handleProxyResponse(ProxyContext context) {
                return Future.<Future<Void>>future(promise -> {
                    try {
                        // Process the proxy context to handle roles, permissions, and claims.
                        processProxyContext(context);
                        promise.complete(context.sendResponse());
                    } catch (Throwable t) {
                        promise.fail(t);
                    }
                }).compose(Function.identity()).onFailure(failure -> {
                    log.error("proxy response error", failure);
                });
            }
        };
    }

    /**
     * Processes the ProxyContext by extracting JWT tokens, validating roles and permissions,
     * and adding claims as headers in the response.
     *
     * @param proxyContext the ProxyContext containing the request and response.
     * @throws JsonProcessingException if an error occurs while processing JSON.
     */
    private void processProxyContext(ProxyContext proxyContext) throws JsonProcessingException {
        // Check if the response status is not 2xx successful
        if (!HttpStatus.valueOf(proxyContext.response().getStatusCode()).is2xxSuccessful()) {
            return;
        }
        var tokenContext = TokenContext.from(proxyContext.response().headers(), ACCESS_TOKEN_HEADER_NAME)
                .orElseThrow(() -> new IllegalArgumentException("unable to parse token context"));
        // Check roles and permissions, add them to headers if found
        for (var claimName : StreamEx.of(config.getRolesClaim(), config.getPermissionsClaim()).nonNull()) {
            var requiredValueSets = requestValues(proxyContext.response(), claimName);
            Set<String> claimValues = tokenContext.claims(claimName)
                    .flatCollection(ForwardAuthProxyVerticle::parseKeys)
                    .toImmutableSet();
            if (!requiredValueSets.isEmpty() && requiredValueSets.stream().noneMatch(claimValues::containsAll)) {
                log.warn("required claim not found - sub:{} claim:{} requiredValues:{} claimValues:{} redirectUri:{}",
                         claimName,
                         tokenContext.accessToken().subject,
                         requiredValueSets,
                         claimValues,
                        config.getRequestAccessUri());
                requestAccess(proxyContext);
                return;
            }
            if (!claimValues.isEmpty()) {
                proxyContext.response().putHeader(headerName(AUTH_REQUEST_HEADER_NAME_PREFIX, claimName), String.join(",", claimValues));
            }
        }
        log.debug("authorized user - sub:{}", tokenContext.accessToken().subject);

        // Add claims to response headers
        for (var ent : EntryStream.of("access-token",
                                      tokenContext.accessTokenContext(),
                                      "id-token",
                                      tokenContext.idTokenContext().orElse(null)).nonNullValues()) {
            var type = ent.getKey();
            var jwtContext = ent.getValue();
            Map<String, Set<String>> claimHeaderMap = jwtContext.allClaims()
                    .mapKeys(v -> headerName(AUTH_REQUEST_HEADER_NAME_PREFIX, type, "claims", v))
                    .mapToValuePartial((k, v) -> headerValue(v))
                    .groupingTo(LinkedHashMap::new, LinkedHashSet::new);
            claimHeaderMap.forEach((headerName, headerValues) -> {
                for (var headerValue : headerValues) {
                    proxyContext.response().headers().add(headerName, headerValue);
                }
            });
        }

        // Remove original token headers and set the authorization header
        Stream.of(ACCESS_TOKEN_HEADER_NAME, ID_TOKEN_HEADER_NAME).forEach(proxyContext.response().headers()::remove);
        String idTokenHeaderName;
        String idTokenHeaderValue = tokenContext.accessTokenContext().encodedJWT();
        if (config.isAccessTokenAuthenticationHeader()) {
            idTokenHeaderName = HttpHeaders.AUTHORIZATION.toString();
            idTokenHeaderValue = "Bearer " + idTokenHeaderValue;
        } else {
            idTokenHeaderName = ACCESS_TOKEN_HEADER_NAME;
        }
        proxyContext.response().headers().set(idTokenHeaderName, idTokenHeaderValue);
        tokenContext.idTokenContext().ifPresent(jwtContext -> {
            proxyContext.response().headers().set(ID_TOKEN_HEADER_NAME, jwtContext.encodedJWT());
        });

    }

    /**
     * Requests access by redirecting the response to the configured access request URI.
     *
     * @param proxyContext the ProxyContext containing the request and response.
     * @throws JsonProcessingException if an error occurs while processing JSON.
     */
    private void requestAccess(ProxyContext proxyContext) throws JsonProcessingException {
        ProxyResponse response = proxyContext.response();
        proxyContext.request().release();
        response.headers().clear();
        response.setStatusCode(HttpStatus.FOUND.value());
        response.putHeader(HttpHeaders.LOCATION, config.getRequestAccessUri().toString());
        response.putHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.setBody(Body.body(Buffer.buffer(objectMapper.writeValueAsBytes(Map.of("message", HttpStatus.UNAUTHORIZED.getReasonPhrase())))));
    }



    /**
     * Converts a header value to a string, handling different types of JSON nodes.
     *
     * @param value the header value.
     * @return an Optional containing the header value as a string.
     */
    private Optional<String> headerValue(Object value) {
        if (value == null) return Optional.empty();
        var node = Failable.get(() -> objectMapper.convertValue(value, JsonNode.class));
        if (node == null || node.isNull() || ((node.isArray() || node.isObject()) && node.isEmpty())) {
            return Optional.empty();
        } else if (node.isTextual()) {
            return Optional.ofNullable(node.textValue());
        } else {
            return Optional.of(node.toString());
        }
    }

    /**
     * Normalizes a header name by converting it to lowercase and replacing non-alphanumeric characters with hyphens.
     *
     * @param name the original header name.
     * @return the normalized header name.
     */
    private static String headerName(String name, String... names) {
        return StreamEx.ofNullable(names)
                .flatArray(Function.identity())
                .prepend(name)
                .nonNull()
                .flatArray(v -> v.split("[^a-zA-Z0-9]+"))
                .filter(StringUtils::isNotEmpty)
                .map(StringUtils::lowerCase)
                .joining("-");
    }

    /**
     * Extracts required claim values from the query parameters of the response URI.
     *
     * @param response   the ProxyResponse containing the request and response.
     * @param rolesClaim the name of the claim to extract values for.
     * @return a Set of Sets of required claim values.
     */
    private static Set<Set<String>> requestValues(ProxyResponse response, String rolesClaim) {
        if (StringUtils.isEmpty(rolesClaim)) return Set.of();
        UriComponents requestUriComponents = UriComponentsBuilder.fromUriString(response.request().getURI()).build();
        MultiValueMap<String, String> queryParams = requestUriComponents.getQueryParams();
        if (queryParams.isEmpty()) return Set.of();
        return StreamEx.ofNullable(queryParams.get(rolesClaim))
                .flatCollection(Function.identity())
                .filter(StringUtils::isNotEmpty)
                .map(queryParam -> splitValues(queryParam).toImmutableSet())
                .filter(Predicate.not(Set::isEmpty))
                .toImmutableSet();
    }

    /**
     * Splits a string value into distinct, non-empty tokens based on space or comma delimiters.
     *
     * @param value the string value to split.
     * @return a StreamEx of distinct, non-empty tokens.
     */
    private static StreamEx<String> splitValues(String value) {
        return StreamEx.ofNullable(value).flatArray(v -> v.split("[ ,]+")).filter(StringUtils::isNotEmpty).distinct();
    }

    /**
     * Parses keys from a value object, handling different data structures like collections and maps.
     *
     * @param value the value object to parse keys from.
     * @return a Set of parsed keys.
     */
    private static Set<String> parseKeys(Object value) {
        if (value instanceof Collection<?> coll) {
            return StreamEx.of(coll).flatCollection(ForwardAuthProxyVerticle::parseKeys)
                    .toCollectionAndThen(LinkedHashSet::new, Collections::unmodifiableSet);
        } else if (value instanceof Map<?, ?> map) {
            for (var key : List.of("key", "id")) {
                var result = parseKeys(map.get(key));
                if (!result.isEmpty()) {
                    return result;
                }
            }
        } else if (value != null) {
            var str = StringUtils.replace(value.toString(), ",", "");
            return splitValues(str).toCollectionAndThen(LinkedHashSet::new, Collections::unmodifiableSet);
        }
        return Set.of();
    }

}
