package com.lfp.traefik.forwardauth.proxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.net.URI;

/**
 * The configuration class for the ForwardAuthProxyVerticle that handles forwarding and processes data from an upstream OAuth2 proxy.
 */
@Validated
@ConfigurationProperties(prefix = "traefik.forwardauth.proxy")
@Configuration
@FieldDefaults(level = AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Setter
@With
@Slf4j
public class ForwardAuthProxyConfig {

    /**
     * The URI used to request access from the upstream OAuth2 proxy. This must be provided.
     */
    @NotNull
    URI requestAccessUri;

    /**
     * The host of the server where ForwardAuthProxyVerticle is set up. The default value is "0.0.0.0", meaning the server will listen on all available network interfaces.
     */
    @NotBlank
    String serverHost = "0.0.0.0";

    /**
     * The port that the server will listen on. The default value is 8080.
     */
    int serverPort = 8080;

    /**
     * The host of the upstream OAuth2 proxy.
     */
    @NotBlank
    String oauth2ProxyHost = "oauth2-proxy";

    /**
     * The port that the upstream OAuth2 proxy will listen on.
     */
    int oauth2ProxyPort = 4180;

    /**
     * The claim in the response JWT which specifies the roles of the client.
     */
    String rolesClaim = "roles";

    /**
     * The claim in the response JWT which specifies the permissions of the client.
     */
    String permissionsClaim = "permissions";

    boolean accessTokenAuthenticationHeader = true;

    /**
     * Bean for Vertx instance with native transport preference
     * @return Vertx instance
     */
    @Bean
    protected Vertx vertx() {
        VertxOptions options = new VertxOptions().setPreferNativeTransport(true);
        return Vertx.vertx(options);
    }

    /**
     * Bean for ForwardAuthProxyVerticle with required parameters
     * @param objectMapper ObjectMapper instance
     * @param vertx Vertx instance
     * @param config ForwardAuthProxyConfig instance
     * @return ForwardAuthProxyVerticle instance
     */
    @Bean
    protected ForwardAuthProxyVerticle forwardAuthProxyVerticle(ObjectMapper objectMapper, Vertx vertx, ForwardAuthProxyConfig config) {
        ForwardAuthProxyVerticle forwardAuthProxyVerticle = new ForwardAuthProxyVerticle(objectMapper, config);
        vertx.deployVerticle(forwardAuthProxyVerticle);
        log.info("server started - address:{}", forwardAuthProxyVerticle.getStartFuture().join());
        return forwardAuthProxyVerticle;
    }
}
