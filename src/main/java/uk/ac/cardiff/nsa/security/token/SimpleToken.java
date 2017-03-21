package uk.ac.cardiff.nsa.security.token;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import uk.ac.cardiff.nsa.security.secure.EncUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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

            //generate to be shared AES key
            SecretKey key = EncUtils.generateAESCEKKey();
            log.debug("Secret key is [{}]", key);


            byte[] encryptedKey = EncUtils.rsaWrapKey(SharedKey.rsaPubKey, key);
            String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKey);
            log.debug("Secret key encrypted is [{}]", encryptedKey);

            byte[] decryptedKey = EncUtils.rsaUnWrapKey(SharedKey.rsaPrivateKey, encryptedKey);
            String decryptedKeyBase64 = Base64.getEncoder().encodeToString(decryptedKey);
            log.debug("Secret key decrypted key [{}]", decryptedKey);


            //generate random initialisaton vector
            IvParameterSpec spec = EncUtils.generateAESGCMParamSpec();
            log.debug("Initialisation Vector is (something random which needs sharing) [{}]", spec.toString());
            String ivForToken = Base64.getEncoder().encodeToString(spec.getIV());

            //encrypt content
            byte[] encrypted = EncUtils.encryptAESGCM(json, key, spec);

            byte[] decrypted = EncUtils.decryptAESGCM(encrypted, key, spec);

            log.debug("Decrypted for testing [{}]", new String(decrypted));

            String contentEncryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

            log.debug("Encrypted content in base64 is [{}]", contentEncryptedBase64);


            return contentEncryptedBase64 + "." + ivForToken + "." + encryptedKeyBase64;

        } catch (Exception e) {
            log.error("Could not create message hash, login will fail", e);
            throw new SessionAuthenticationException("Hash for token could not be generated");
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
