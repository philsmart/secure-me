
package uk.ac.cardiff.nsa.security.secure.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import javax.annotation.Nullable;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Our basic authentication filter is a lightweight version of springs {@link BasicAuthenticationFilter}.
 */
public class OurBasicAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OurBasicAuthenticationFilter.class);

    private final String username = "test";

    // bigapicall
    private final String password = "CKiSIBlBGa7Y+JHwHZ89n3SiAzuXjoaJVJUPonSiEVY=";

    private String credentialsCharset = "UTF-8";

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {

        log.info("Checking basic authentication credentials");

        final String header = request.getHeader("Authorization");

        // if no basic auth in header, crack on
        if (!StringUtils.startsWithIgnoreCase(header, "basic ")) {
            chain.doFilter(request, response);
            return;
        }

        final String[] usernamePassword = extractAndDecodeHeader(header, request);

        if (usernamePassword.length != 2 || usernamePassword[0] == null || usernamePassword[1] == null) {
            log.info("No username and password found in request, continuing");
            chain.doFilter(request, response);
            return;
        }

        log.info("Has Found username [{}] and password [{}]", usernamePassword[0], usernamePassword[1]);

        if (usernamePassword[1] != null) {
            final Optional<String> passwordAsBase64Hash = hashStringToBase64(usernamePassword[1]);
            if (passwordAsBase64Hash.isPresent()) {
                if (password.equals(passwordAsBase64Hash.get()) && username.equals(usernamePassword[0])) {
                    log.info("Username and password match!");

                    final List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

                    final Authentication authentication = new UsernamePasswordAuthenticationToken(usernamePassword[0],
                            usernamePassword[1], authorities);

                    // this effectively is a authenticated identity.
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                }
            }
        }

        // always pass down the chain at the end
        chain.doFilter(request, response);

    }

    private Optional<String> hashStringToBase64(@Nullable final String password) {

        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] encodedhash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            final byte[] base64PasswordBytes = Base64.getEncoder().encode(encodedhash);
            final String base64PasswordString = new String(base64PasswordBytes);
            return Optional.of(base64PasswordString);
        } catch (final NoSuchAlgorithmException e) {
            log.error("Unable to hash to base64 input password", e);
        }
        return Optional.empty();

    }

    /**
     * Decodes the header into a username and password.
     *
     * @throws BadCredentialsException if the Basic header is not present or is not valid Base64
     */
    private String[] extractAndDecodeHeader(final String header, final HttpServletRequest request) throws IOException {

        final byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Token);
        } catch (final IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        final String token = new String(decoded, credentialsCharset);

        final int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[] {token.substring(0, delim), token.substring(delim + 1)};
    }

}
