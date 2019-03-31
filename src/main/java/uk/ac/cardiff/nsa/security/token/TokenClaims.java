
package uk.ac.cardiff.nsa.security.token;

public class TokenClaims {

    private long issuedAt;

    private long validFor;

    private String role;

    private String principalName;

    private String nonce;

    /**
     * Time since epoch
     */
    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(final long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getValidFor() {
        return validFor;
    }

    public void setValidFor(final long validFor) {
        this.validFor = validFor;
    }

    public String getRole() {
        return role;
    }

    public void setRole(final String role) {
        this.role = role;
    }

    /**
     * First iteration we simply called this username.
     */
    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(final String principalName) {
        this.principalName = principalName;
    }

    /**
     * @return Returns the nonce.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * @param nonce The nonce to set.
     */
    public void setNonce(final String nonce) {
        this.nonce = nonce;
    }
}
