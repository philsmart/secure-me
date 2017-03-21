package uk.ac.cardiff.nsa.security.secure;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

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
        SecretKey sk = new SecretKeySpec(new byte[16], "AES");
        return sk;
    }

    /**
     * Encrypt the message using AES GCM with no padding. Which is sufficient for AEAD.
     * GCM is an authenticated encryption mode with "additional data" (often referred to as AEAD).
     * <p>
     * NOTE, Changed to CBC (code block) as need to fix GMC
     *
     * @param message    the {@link String} to encrypt
     * @param key        the {@link java.security.Key} to encrypt with
     * @param initVector add randomness to the encryption, this needs to be shared with resource server.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] encryptAESGCM(String message, SecretKey key, IvParameterSpec initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key, initVector);
        byte[] encrypted = cipher.doFinal(message.getBytes());

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
    public static byte[] decryptAESGCM(byte[] message, SecretKey key, IvParameterSpec initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, key, initVector);
        byte[] decrypted = cipher.doFinal(message);

        return decrypted;

    }

    public static IvParameterSpec generateAESGCMParamSpec() throws InvalidParameterSpecException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte iv[] = new byte[16];//generate random 16 byte IV AES is always 16bytes
        random.nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        return ivspec;
    }

    public static byte[] rsaWrapKey(Key rsaPublicKey, SecretKey keyToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        return cipher.doFinal(keyToEncrypt.getEncoded());

    }

    public static byte[] rsaUnWrapKey(Key rsaPrivateKey, byte[] keyToDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return cipher.doFinal(keyToDecrypt);

    }
}
