package com.lfp.traefik.forwardauth.proxy.jwt;

import io.fusionauth.jwt.domain.JWT;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.impl.headers.HeadersMultiMap;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.experimental.FieldDefaults;
import one.util.streamex.StreamEx;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.BooleanConsumer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

@FieldDefaults(level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Getter
@Accessors(fluent = true)
public class TokenContext implements ClaimReader {

    private static final String ACCESS_TOKEN_HEADER_NAME = "x-auth-request-access-token";

    @NonNull
    final JWTContext accessTokenContext;
    final JWTContext idTokenContext;
    @Getter(AccessLevel.NONE)
    transient Map<String, Object> _allClaims;

    public JWT accessToken() {
        return accessTokenContext().jwt().orElseThrow();
    }

    public Optional<JWTContext> idTokenContext() {
        return Optional.ofNullable(idTokenContext);
    }

    public Optional<JWT> idToken() {
        return idTokenContext().flatMap(JWTContext::jwt);
    }


    @Override
    public Map<String, Object> getAllClaims() {
        if (this._allClaims == null) {
            var allClaims = StreamEx.of(accessTokenContext().allClaims(), idTokenContext().map(ClaimReader::allClaims).orElse(null))
                    .flatMap(Function.identity())
                    .mapToEntry(Map.Entry::getKey, Map.Entry::getValue)
                    .distinctKeys()
                    .toCustomMap(LinkedHashMap::new);
            this._allClaims = Collections.unmodifiableMap(allClaims);
        }
        return this._allClaims;
    }


    public static Optional<TokenContext> from(MultiMap headers, String accessTokenHeaderName, String... accessTokenHeaderNames) {
        if (headers == null || headers.isEmpty()) return Optional.empty();
        HeadersMultiMap headersMultiMap;
        if (headers instanceof HeadersMultiMap) {
            headersMultiMap = (HeadersMultiMap) headers;
        } else {
            headersMultiMap = new HeadersMultiMap();
            headersMultiMap.addAll(headers);
        }
        return from(headersMultiMap::getAll, accessTokenHeaderName, accessTokenHeaderNames);
    }

    public static Optional<TokenContext> from(Function<String, ? extends Iterable<String>> headerFn,
                                              String accessTokenHeaderName,
                                              String... accessTokenHeaderNames) {
        if (headerFn == null) return Optional.empty();
        Function<StreamEx<String>, StreamEx<JWTContext>> jwtContextStreamFn = headerNames -> {
            headerNames = StreamEx.ofNullable(headerNames)
                    .flatMap(Function.identity())
                    .append(HttpHeaders.AUTHORIZATION.toString())
                    .filter(StringUtils::isNotEmpty)
                    .distinct();

            return headerNames.distinct()
                    .map(headerFn)
                    .nonNull()
                    .map(Iterable::spliterator)
                    .flatMap(StreamEx::of)
                    .mapPartial(JWTContext::from);
        };
        var accessTokenContext = jwtContextStreamFn.apply(StreamEx.ofNullable(accessTokenHeaderNames)
                                                                  .flatArray(Function.identity())
                                                                  .prepend(accessTokenHeaderName))
                .filter(v -> v.jwt().isPresent())
                .findFirst()
                .orElse(null);
        if (accessTokenContext == null) return Optional.empty();
        var idTokenContext = jwtContextStreamFn.apply(null)
                .filter(Predicate.not(accessTokenContext::equals))
                .filter(v -> v.jwt()
                        .isPresent()).findFirst().orElse(null);
        return Optional.of(new

                                   TokenContext(accessTokenContext, idTokenContext));

    }
}
