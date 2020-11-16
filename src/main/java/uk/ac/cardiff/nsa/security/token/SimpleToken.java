
package uk.ac.cardiff.nsa.security.token;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import uk.ac.cardiff.nsa.security.secure.EncUtils;

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

            // generate to be shared AES key
            final SecretKey key = EncUtils.generateAESCEKKey();
            log.debug("Secret key is [{}]", Base64.getEncoder().encodeToString(key.getEncoded()));

            log.debug("public key is [{}]", Base64.getEncoder().encodeToString(SharedKey.rsaPubKey.getEncoded()));
            log.debug("private key is [{}]", Base64.getEncoder().encodeToString(SharedKey.rsaPrivateKey.getEncoded()));

            // final byte[] encryptedKey = EncUtils.rsaWrapKey(SharedKey.rsaPubKey, key.getEncoded());

            final byte[] encryptedKey = EncUtils.rsaWrapKey(SharedKey.rsaPubKey, key.getEncoded());
            log.debug("Encrypted key bytes [{}]", encryptedKey);

            final String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKey);
            log.debug("Secret key encrypted is [{}]", encryptedKeyBase64);

            //this is for debug only, to check the key wrapping worked.
            final byte[] decryptedKey = EncUtils.rsaUnWrapKey(SharedKey.rsaPrivateKey, encryptedKey);
            final String decryptedKeyBase64 = Base64.getEncoder().encodeToString(decryptedKey);
            log.debug("Secret key decrypted key [{}]", decryptedKeyBase64);

            // generate random initialisaton vector
            final IvParameterSpec spec = EncUtils.generateAESGCMParamSpec();
            log.debug("Initialisation Vector is (something random which needs sharing) [{}]", spec.toString());
            final String ivForToken = Base64.getEncoder().encodeToString(spec.getIV());

            // encrypt content
            final byte[] encrypted = EncUtils.encryptAESGCM(json, key, spec);

            final byte[] decrypted = EncUtils.decryptAESGCM(encrypted, key, spec);

            log.debug("Decrypted for testing [{}]", new String(decrypted));

            final String contentEncryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

            log.debug("Encrypted content in base64 is [{}]", contentEncryptedBase64);

            return contentEncryptedBase64 + "." + ivForToken + "." + encryptedKeyBase64;

        } catch (final Exception e) {
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
