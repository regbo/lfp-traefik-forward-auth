package com.lfp.traefik.forwardauth.proxy;

import io.fusionauth.jwt.JWTException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.JWT;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.experimental.FieldDefaults;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class provides a context for handling JWTs, including basic parsing and checking
 * for validity. It does not perform any validation, as that is handled by the upstream
 * OAuth2 proxy.
 */
@SuppressWarnings({"OptionalAssignedToNull", "OptionalUsedAsFieldOrParameterType"})
@FieldDefaults(level = AccessLevel.PRIVATE)
@Accessors(fluent = true)
@Getter
@EqualsAndHashCode
public class JWTContext {
    // Pattern to match JWT strings
    private static final Pattern JWT_PATTERN = Pattern.compile("^(bearer\\s+)?([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+(\\.[A-Za-z0-9-_]+)?$)",
            Pattern.CASE_INSENSITIVE);
    // Insecure verifier that accepts all algorithms
    private static final Verifier INSECURE_VERIFIER = new Verifier() {
        @Override
        public boolean canVerify(Algorithm algorithm) {
            return true;
        }

        @Override
        public void verify(Algorithm algorithm, byte[] bytes, byte[] bytes1) {
            // No verification performed
        }
    };

    @NotNull
    final String encodedJWT; // Encoded JWT string
    @EqualsAndHashCode.Exclude
    transient Optional<JWT> jwt; // Parsed JWT, lazily initialized

    /**
     * Constructs a new JWTContext with the given encoded JWT.
     *
     * @param encodedJWT the encoded JWT string
     */
    protected JWTContext(String encodedJWT) {
        this.encodedJWT = encodedJWT;
    }

    /**
     * Lazily decodes and returns the JWT. If decoding fails, returns an empty Optional.
     *
     * @return an Optional containing the decoded JWT, or empty if decoding fails
     */
    public Optional<JWT> jwt() {
        if (jwt == null) {
            try {
                // Decode the JWT using the insecure verifier
                jwt = Optional.ofNullable(JWT.getDecoder().decode(encodedJWT(), INSECURE_VERIFIER));
            } catch (JWTException e) {
                jwt = Optional.empty();
            }
        }
        return jwt;
    }

    /**
     * Creates a JWTContext from a source string if it contains a valid JWT.
     *
     * @param source the source string potentially containing a JWT
     * @return an Optional containing the JWTContext, or empty if the source does not contain a valid JWT
     */
    public static Optional<JWTContext> from(String source){
        return Optional.ofNullable(source)
                .filter(StringUtils::isNotEmpty) // Ensure the source is not empty
                .map(JWT_PATTERN::matcher) // Match the source against the JWT pattern
                .filter(Matcher::find) // Check if the pattern matches
                .map(matcher -> matcher.group(2)) // Extract the JWT
                .map(JWTContext::new); // Create a new JWTContext
    }
}
