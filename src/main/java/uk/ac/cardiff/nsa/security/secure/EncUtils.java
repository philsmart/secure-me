
package uk.ac.cardiff.nsa.security.secure;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by philsmart on 21/03/2017.
 */
public class EncUtils {

    /**
     * Generate a content encryption key. Which is used to encrypt the content - is an 128bit AES symmetric key.
     *
     * @return
     */
    public static SecretKey generateAESCEKKey() {
        final SecretKey sk = new SecretKeySpec(new byte[16], "AES");
        return sk;
    }

    /**
     * Encrypt the message using AES GCM with no padding. Which is sufficient for AEAD. GCM is an authenticated
     * encryption mode with "additional data" (often referred to as AEAD).
     * <p>
     * NOTE, Changed to CBC (code block) as need to fix GMC
     *
     * @param message the {@link String} to encrypt
     * @param key the {@link java.security.Key} to encrypt with
     * @param initVector add randomness to the encryption, this needs to be shared with resource server.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] encryptAESGCM(final String message, final SecretKey key, final IvParameterSpec initVector)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key, initVector);
        final byte[] encrypted = cipher.doFinal(message.getBytes());

        return encrypted;

    }

    /**
     * This should use GCM, uses CBC for now
     *
     * @param message
     * @param key
     * @param initVector
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] decryptAESGCM(final byte[] message, final SecretKey key, final IvParameterSpec initVector)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, key, initVector);
        final byte[] decrypted = cipher.doFinal(message);

        return decrypted;

    }

    public static IvParameterSpec generateAESGCMParamSpec()
            throws InvalidParameterSpecException, NoSuchPaddingException, NoSuchAlgorithmException {
        final SecureRandom random = new SecureRandom();
        final byte iv[] = new byte[16];// generate random 16 byte IV AES is always 16bytes
        random.nextBytes(iv);
        final IvParameterSpec ivspec = new IvParameterSpec(iv);

        return ivspec;
    }

    public static byte[] rsaWrapKey(final Key rsaPublicKey, final byte[] keyToEncrypt) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        return cipher.doFinal(keyToEncrypt);

    }

    public static byte[] rsaUnWrapKey(final Key rsaPrivateKey, final byte[] keyToDecrypt) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return cipher.doFinal(keyToDecrypt);

    }
}
