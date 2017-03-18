package uk.ac.cardiff.nsa.security.token;

import org.json.JSONObject;
import org.springframework.security.crypto.codec.Base64;

/**
 * Ignore for now. This is more sophisticated version.
 */
public class SimpleToken {

    private TokenClaims claims = new TokenClaims();


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

        return new String(Base64.encode(json.getBytes()));
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
