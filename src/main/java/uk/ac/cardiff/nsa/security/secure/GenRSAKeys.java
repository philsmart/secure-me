package uk.ac.cardiff.nsa.security.secure;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by philsmart on 21/03/2017.
 */
public class GenRSAKeys {

    public static void main(String args[]) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair kp = keyGen.genKeyPair();
        byte[] publicKey = kp.getPublic().getEncoded();
        System.out.print(publicKey);
    }
}
