
package uk.ac.cardiff.nsa.security.secure.auth;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import uk.ac.cardiff.nsa.security.secure.EncUtils;
import uk.ac.cardiff.nsa.security.token.SharedKey;

/**
 * Created by philsmart on 13/03/2017.
 */

public class CustomTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(CustomTokenAuthenticationFilter.class);

    public CustomTokenAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/**"));
        setAuthenticationManager(new NoopAuthenticationManager());
        setAuthenticationSuccessHandler(new SuccessfulTokenAuth());
    }

    /**
     * Performs actual authentication.
     * <p>
     * The implementation should do one of the following:
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress. Before returning, the
     * implementation should perform any additional work required to complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * </ol>
     *
     * @param request from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a redirect as part of a
     *            multi-stage authentication process (such as OpenID).
     * @return the authenticated user token, or null if authentication is incomplete.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        log.info("Doing my kind of token authentication");

        final String header = request.getHeader("Authorization");

        log.debug("Has Authorization header [{}]", header);

        final String authHeader = header.replace("Basic ", "");

        try {
            // will fail here with BadCredentialsException if not valid
            final ValidToken token = validateToken(authHeader);

            log.debug("Token was validated, user {} with role {}", token.getUsername(), token.getRole());

            final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority(token.getRole()));

            final UsernamePasswordAuthenticationToken upToken =
                    new UsernamePasswordAuthenticationToken(token.getUsername(), null, authorities);

            // throw new BadCredentialsException("Bad username/password");
            return upToken;
        } catch (final InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException
                | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {

            log.error("Error decrypting json content", e);
            throw new BadTokenException("Error descrypting json content", e);
        }

    }

    @Nonnull
    private ValidToken validateToken(@Nonnull final String token)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {

        if (token.contains(".") == false) {
            throw new BadTokenException("Token does not contain digest (hash)");
        }

        final String[] splitToken = token.split("\\.");

        if (splitToken.length != 3) {
            throw new BadTokenException("Token length is invalid (needs to be 3), length is " + splitToken.length);

        }

        log.debug("Content secure [{}]", splitToken[0]);
        log.debug("Key secure [{}]", splitToken[2]);
        log.debug("Secure initVector [{}]", splitToken[1]);

        final byte[] secureContentDecoded = Base64.decode(splitToken[0].getBytes());
        final byte[] secureAesKeyDecoded = Base64.decode(splitToken[2].getBytes());
        final byte[] secureInitVectorDecoded = Base64.decode(splitToken[1].getBytes());

        log.debug("Content secure [{}]", Base64.encode(secureContentDecoded));
        log.debug("Key secure [{}]", Base64.encode(secureAesKeyDecoded));
        log.debug("Secure initVector [{}]", Base64.encode(secureInitVectorDecoded));

        final byte[] decryptedKey = EncUtils.rsaUnWrapKey(SharedKey.rsaPrivateKey, secureAesKeyDecoded);
        final String decryptedKeyBase64 = new String(Base64.encode(decryptedKey));
        log.debug("Secret key decrypted key [{}]", decryptedKeyBase64);

        final IvParameterSpec ivspec = new IvParameterSpec(secureInitVectorDecoded);
        final SecretKey sk = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
        final byte[] decrypted = EncUtils.decryptAESGCM(secureContentDecoded, sk, ivspec);

        final String decryptedJson = new String(decrypted);
        log.debug("Decrypted Text is [{}]", new String(decrypted));

        final JSONObject tokenJson = new JSONObject(decryptedJson);

        final String role = tokenJson.getString("role");
        final Long validFor = tokenJson.getLong("validFor");
        final Long issuedAt = tokenJson.getLong("issuedAt");
        final String principal = tokenJson.getString("principalName");

        final long currentTime = System.currentTimeMillis();

        if (issuedAt + validFor < currentTime) {
            log.warn("Token is no longer valid, expired at {}, is now {}", issuedAt + validFor, currentTime);
            throw new SessionAuthenticationException("Token no longer valid");
        }

        if (role.startsWith("ROLE") == false) {
            throw new BadCredentialsException("User roles not found in access token");
        }

        return new ValidToken(principal, role);
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain, final Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        log.info("SuccessfulAuthentication, continuing on filter chain");
        // continue if no authentication exception
        chain.doFilter(request, response);
    }

    private static class SuccessfulTokenAuth implements AuthenticationSuccessHandler {

        /**
         * Called when a user has been successfully authenticated.
         *
         * @param request the request which caused the successful authentication
         * @param response the response
         * @param authentication the <tt>Authentication</tt> object which was created during
         */
        @Override
        public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
                final Authentication authentication) throws IOException, ServletException {
            log.info(
                    "Authentication is succesful, no redirects, just continue through the filter chain until we get to the resource requested");
        }
    }

    /**
     * We are not going to delegate to an {@link AuthenticationManager}, we do not require that level of customisation.
     * Everything we do will be in the {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)} method.
     */
    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }

}

class ValidToken {

    private final String username;

    private final String role;

    public ValidToken(final String username, final String role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }
}
