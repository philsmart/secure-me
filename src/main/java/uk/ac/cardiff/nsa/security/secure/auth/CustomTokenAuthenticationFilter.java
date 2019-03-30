package uk.ac.cardiff.nsa.security.secure.auth;

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
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.annotation.Nonnull;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
     * <li>Return a populated authentication token for the authenticated user, indicating
     * successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress.
     * Before returning, the implementation should perform any additional work required to
     * complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * </ol>
     *
     * @param request  from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a
     *                 redirect as part of a multi-stage authentication process (such as OpenID).
     * @return the authenticated user token, or null if authentication is incomplete.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        log.info("Doing my kind of token authentication");

        String header = request.getHeader("Authorization");

        log.debug("Has Authorization header [{}]",header);

        final String authHeader = header.replace("Basic ", "");

        final byte[] authHeaderDecoded = Base64.decode(authHeader.getBytes());

        //will fail here with BadCredentialsException if not valid
        ValidToken token = validateToken(new String(authHeaderDecoded));

        log.debug("Token was validated, user {} with role {}", token.getUsername(), token.getRole());

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(token.getRole()));

        HttpSessionSecurityContextRepository np;

        UsernamePasswordAuthenticationToken upToken = new UsernamePasswordAuthenticationToken(token.getUsername(), null, authorities);

        // throw new BadCredentialsException("Bad username/password");
        return upToken;


    }

    @Nonnull
    private ValidToken validateToken(@Nonnull String token) {

        //these will throw auth execptions if not found - one check.
        final String username = getUsernameFromBasicAuthString(token);
        final String role = getRoleFromBasicAuthString(token);

        if (role.startsWith("ROLE") == false) {
            throw new BadCredentialsException("User roles not found in access token");
        }

        return new ValidToken(username, role);
    }


    @Nonnull
    private String getUsernameFromBasicAuthString(final String authString) {


        final String[] userPass = authString.split(":");

        if (userPass.length == 2) {
            return userPass[0];
        } else {
            log.warn("Authorisation header invalid, contains {} components, should be 2", userPass.length);
            throw new BadCredentialsException("Authorisation header invalid, no username found");
        }
    }

    @Nonnull
    private String getRoleFromBasicAuthString(final String authString) {


        final String[] userPass = authString.split(":");

        if (userPass.length == 2) {
            return userPass[1];
        } else {
            log.warn("Authorisation header invalid, contains {} components, should be 2", userPass.length);
            throw new BadCredentialsException("Authorisation header invalid, no roles found");
        }
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        log.info("SuccessfulAuthentication, continuing on filter chain");
        //continue if no authentication exception
        chain.doFilter(request, response);
    }


    private static class SuccessfulTokenAuth implements AuthenticationSuccessHandler{

        /**
         * Called when a user has been successfully authenticated.
         *
         * @param request        the request which caused the successful authentication
         * @param response       the response
         * @param authentication the <tt>Authentication</tt> object which was created during
         */
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            log.info("Authentication is succesful, no redirects, just continue through the filter chain until we get to the resource requested");
        }
    }

    /**
     * We are not going to delegate to an {@link AuthenticationManager}, we do not require that level of customisation. Everything we do will be
     * in the {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)} method.
     */
    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }


}

class ValidToken {

    private final String username;

    private final String role;

    public ValidToken(String username, String role) {
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
