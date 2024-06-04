package com.lfp.traefik.forwardauth.proxy.jwt;

import one.util.streamex.EntryStream;
import one.util.streamex.StreamEx;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

public interface ClaimReader {

    Map<String, Object> getAllClaims();

    default EntryStream<String, Object> allClaims() {
        var claims = getAllClaims();
        if (claims == null || claims.isEmpty()) return EntryStream.empty();
        return EntryStream.of(claims);
    }

    default StreamEx<Object> claims(String key, String... keys) {
        var claims = getAllClaims();
        if (claims == null || claims.isEmpty()) return StreamEx.empty();
        return StreamEx.ofNullable(keys)
                .flatArray(Function.identity())
                .prepend(key)
                .filter(StringUtils::isNotEmpty)
                .distinct().map(claims::get).nonNull();

    }
}
