package uk.ac.cardiff.nsa.security.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple user repository to store statically defined, in-memory, users
 */
@Component
public class UserRepository {

    private static final Logger log = LoggerFactory.getLogger(UserRepository.class);


    private Map<String, User> users = new HashMap<String, User>();


    @PostConstruct
    public void createUsers() {
        log.info("Creating test API users");
        users.put("testuser", new User("Test user one", "testuser", "test1".toCharArray()));

    }


    /**
     * Authenticates credentials against users in the {@code users} map.
     *
     * @param username the username of the {@link User}
     * @param password the password of the {@link User}
     * @return the {@link User} object that authenticated to the username and password.
     * @throws BadCredentialsException if a {@link User} could not authenticate against the username and password
     */
    @Nonnull
    public User authenticate(@Nonnull String username, @Nonnull String password) throws BadCredentialsException {

        User foundUser = users.get(username);

        log.debug("Found user [{}]", foundUser == null ? "none" : foundUser.getUsername());

        if (foundUser != null && Arrays.equals(foundUser.getPassword(), password.toCharArray())) {
            return foundUser;
        }

        throw new BadCredentialsException("User not found");


    }


}
