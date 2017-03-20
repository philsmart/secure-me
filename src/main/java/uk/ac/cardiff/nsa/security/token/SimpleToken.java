package uk.ac.cardiff.nsa.security.token;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import uk.ac.cardiff.nsa.security.secure.HashUtils;

import java.util.Base64;

/**
 * Ignore for now. This is more sophisticated version.
 */
public class SimpleToken {

    private TokenClaims claims = new TokenClaims();

    private static final Logger log = LoggerFactory.getLogger(SimpleToken.class);


    public static Builder builder() {

        return new SimpleToken.Builder();

    }

    /**
     * Build a serialised token.
     *
     * @return a String representation of this token.
     */
    public String generate() {

        final JSONObject claimsAsJson = new JSONObject(claims);
        final String json = claimsAsJson.toString();

        try {
            String hmac = HashUtils.hmac256(json, SharedKey.sharedKey);

            return Base64.getEncoder().encodeToString(json.getBytes()) + "." + hmac;

        } catch (Exception e) {
            log.error("Could not create message hash, login will fail", e);
            throw new SessionAuthenticationException("Has for token could not be generated");
        }

    }



    public static class Builder {

        private SimpleToken instance = new SimpleToken();

        public Builder setPrincipalName(final String name) {
            instance.claims.setPrincipalName(name);
            return this;
        }

        public Builder setIssuedAt(final long iat) {
            instance.claims.setIssuedAt(iat);
            return this;
        }

        public Builder setValidFor(final long validFor) {
            instance.claims.setValidFor(validFor);
            return this;
        }

        public Builder setRole(final String role) {
            instance.claims.setRole(role);
            return this;
        }

        public SimpleToken build() {

            return instance;

        }


    }


}
