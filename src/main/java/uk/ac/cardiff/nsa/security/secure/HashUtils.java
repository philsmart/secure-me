package uk.ac.cardiff.nsa.security.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by philsmart on 19/03/2017.
 */
public class HashUtils {

    private static final Logger log = LoggerFactory.getLogger(HashUtils.class);

    /**
     * Generate a base64 encoding of the SHA-256 hash of the input message
     *
     * @param message the message to hash
     * @return a base64 representation of the hash.
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    @Nonnull
    public static String messageHash(@Nonnull final String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        log.debug("Hashing message [{}]", message);
        final byte[] hash = digest.digest(message.getBytes("UTF-8"));

        log.debug("Hash is {}", hash);
        log.debug("Hash has size {}", hash.length);
        log.debug("Hash as string [{}]", new String(hash, StandardCharsets.ISO_8859_1));
        final String base64Hash = Base64.getEncoder().encodeToString(hash);
        log.debug("Hash as base64 string is [{}]", base64Hash);


        return base64Hash;

    }
}
