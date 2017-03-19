package uk.ac.cardiff.nsa.security.secure.auth;

import org.springframework.security.core.AuthenticationException;

/**
 * Created by philsmart on 19/03/2017.
 */
public class BadTokenException extends AuthenticationException {

    /**
     * Constructs an {@code AuthenticationException} with the specified message and root
     * cause.
     *
     * @param msg the detail message
     * @param t   the root cause
     */
    public BadTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an {@code AuthenticationException} with the specified message and no
     * root cause.
     *
     * @param msg the detail message
     */
    public BadTokenException(String msg) {
        super(msg);
    }
}
