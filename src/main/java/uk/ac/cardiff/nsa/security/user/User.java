
package uk.ac.cardiff.nsa.security.user;

import java.util.Objects;

import javax.annotation.Nonnull;

import uk.ac.cardiff.nsa.security.token.SimpleToken;

/**
 * Created by philsmart on 15/03/2017.
 */
public class User {

    private String name;

    private String role;

    private String username;

    /**
     * From http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx It would seem
     * logical to collect and store the password in an object of type java.lang.String. However, here's the caveat:
     * Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or
     * zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security
     * sensitive information such as user passwords. You should always collect and store security sensitive information
     * in a char array instead.
     */
    private char[] password;

    /**
     * Constructor to initialse all values of this {@link User}.
     *
     * @param name the users name
     * @param username the username of the user
     * @param password the password of the user (plain text)
     */
    public User(@Nonnull final String name, @Nonnull final String username, @Nonnull final char[] password) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);
        Objects.requireNonNull(name);
        this.setUsername(username);
        this.setName(name);
        this.setPassword(password);
        role = "ROLE_USER";
    }

    public SimpleToken generateToken() {

        final SimpleToken token = SimpleToken.builder().setPrincipalName(username).setRole(role)
                .setIssuedAt(System.currentTimeMillis()).setValidFor(60000).build();

        return token;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(final char[] password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(final String role) {
        this.role = role;
    }
}
