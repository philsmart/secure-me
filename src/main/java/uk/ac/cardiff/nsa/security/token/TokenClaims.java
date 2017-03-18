package uk.ac.cardiff.nsa.security.token;

/**
 * Created by philsmart on 18/03/2017.
 */
public class TokenClaims {

    private long issuedAt;

    private long validFor;

    private String role;

    private String principalName;

    /**
     * Time since epoch
     */
    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getValidFor() {
        return validFor;
    }

    public void setValidFor(long validFor) {
        this.validFor = validFor;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    /**
     * First iteration we simply called this username.
     */
    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }
}
