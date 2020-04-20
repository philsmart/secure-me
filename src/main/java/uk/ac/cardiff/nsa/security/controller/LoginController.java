package uk.ac.cardiff.nsa.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import uk.ac.cardiff.nsa.security.token.TokenRepository;
import uk.ac.cardiff.nsa.security.user.User;
import uk.ac.cardiff.nsa.security.user.UserRepository;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 * Created by philsmart on 13/03/2017.
 */
@RestController
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    /**
     * The shared {@link UserRepository} for login and API authentication.
     */
    @Inject
    private UserRepository userRepo;


    @Inject
    private TokenRepository tokenRepository;

    @RequestMapping(value = "/login", method= RequestMethod.GET, produces ="application/json" )
    public ResponseEntity<String> login(HttpServletRequest request){

        log.info("Login request");

        final String auth = request.getHeader("Authorization");
        
        if (auth==null){
        	log.info("No credentials in request");
        	return new ResponseEntity<String>("",HttpStatus.UNAUTHORIZED);
        }

        log.debug("Has auth header [{}]",auth);

        final String authUsernamePassword = auth.replace("Basic ", "");

        final byte[] decodedUsernamePassword = Base64.decode(authUsernamePassword.getBytes());

        final String decodedUserPassString = new String(decodedUsernamePassword);
        
        log.debug("Decoded userpass string {}",decodedUserPassString);

        final String username = getUsernameFromBasicAuthString(decodedUserPassString);
        final String password = getPasswordFromBasicAuthString(decodedUserPassString);

        log.debug("Has decoded username:password (should never show password in log) [usernamne [{}], password [{}]]", username, password);


        final User authenticatedUser = userRepo.authenticate(username, password);

        String accessToken = authenticatedUser.generateToken();

        tokenRepository.getPublishedTokens().add(accessToken);

        log.debug("Generated AccessToken {}", accessToken);

        return new ResponseEntity<String>(accessToken,HttpStatus.OK);


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
    private String getPasswordFromBasicAuthString(final String authString) {


        final String[] userPass = authString.split(":");

        if (userPass.length == 2) {
            return userPass[1];
        } else {
            log.warn("Authorisation header invalid, contains {} components, should be 2", userPass.length);
            throw new BadCredentialsException("Authorisation header invalid, no password found");
        }
    }
}
