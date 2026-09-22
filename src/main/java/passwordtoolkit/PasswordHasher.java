package passwordtoolkit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Salted SHA-256 password hashing, used to demonstrate how passwords should be
 * stored: never in plain text, and never as an unsalted hash.
 *
 * <p>Stored format: {@code base64(salt):base64(sha256(salt || password))}.
 *
 * <p><b>Note:</b> a single round of SHA-256 is fast by design, which makes it
 * cheap to brute-force. Production systems should use a deliberately slow,
 * memory-hard function such as Argon2id, bcrypt or PBKDF2. This class is kept
 * simple so the salting idea is easy to follow.
 */
public final class PasswordHasher {

    private static final int SALT_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {}

    /** Hashes {@code password} with a fresh random salt. */
    public static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return encode(salt, digest(salt, password));
    }

    /** Returns true if {@code password} matches a value produced by {@link #hash}. */
    public static boolean verify(String password, String stored) {
        String[] parts = stored.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Expected salt:hash");
        Base64.Decoder b64 = Base64.getDecoder();
        byte[] salt = b64.decode(parts[0]);
        byte[] expected = b64.decode(parts[1]);
        // Constant-time comparison, so timing does not leak how many bytes matched.
        return MessageDigest.isEqual(expected, digest(salt, password));
    }

    static byte[] digest(byte[] salt, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update(password.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java runtime", e);
        }
    }

    private static String encode(byte[] salt, byte[] hash) {
        Base64.Encoder b64 = Base64.getEncoder();
        return b64.encodeToString(salt) + ":" + b64.encodeToString(hash);
    }
}
