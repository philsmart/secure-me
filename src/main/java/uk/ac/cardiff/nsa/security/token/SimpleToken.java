package uk.ac.cardiff.nsa.security.token;

/**
 * Ignore for now. This is more sophisticated version.
 */
public class SimpleToken {


    private String accessToken;

    /**
     * Time since epoch
     */
    private long issuedAt;

    private long validFor;


    public static Builder builder() {

        return new SimpleToken.Builder();

    }

    public static class Builder {

        private SimpleToken instance = new SimpleToken();


        public Builder setToken(final String token) {
            instance.accessToken = token;
            return this;
        }

        public Builder setIssuedAt(final Long iat) {
            instance.issuedAt = iat;
            return this;
        }

        public SimpleToken build() {

            return instance;

        }


    }


}
