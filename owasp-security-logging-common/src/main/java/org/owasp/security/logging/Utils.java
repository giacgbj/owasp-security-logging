package org.owasp.security.logging;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * Utilities methods for logging.
 *
 * @author August Detlefsen [augustd@codemagi.com]
 */
public class Utils {

    /**
     * Converts an input String to a SHA hash. The actual hash strength is hidden by the method name to allow for future-proofing this API, but the current default is SHA-256.
     *
     * @param input
     *            The string to hash
     * @return SHA hash of the input String, hex encoded.
     */
    public static String toSHA(final String input) {
        return toSHA(input.getBytes());
    }

    /**
     * Converts an input byte array to a SHA hash. The actual hash strength is hidden by the method name to allow for future-proofing this API, but the current default is SHA-256.
     *
     * @param input
     *            Byte array to hash
     * @return SHA hash of the input String, hex encoded.
     */
    public static String toSHA(final byte[] input) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            return byteArray2Hex(md.digest(input));
        } catch (@SuppressWarnings("unused") final NoSuchAlgorithmException nsae) {
            // this code should never be reached!
        }
        return null;
    }

    /**
     * Converts an input byte array to a hex encoded String.
     *
     * @param input
     *            Byte array to hex encode
     * @return Hex encoded String of the input byte array
     */
    private static String byteArray2Hex(final byte[] hash) {
        try (Formatter formatter = new Formatter();) {
            for (final byte b : hash) {
                formatter.format("%02x", b);
            }
            final String hex = formatter.toString();
            return hex;
        }
    }

    /**
     * Determines if a string is null or empty
     *
     * @param value
     *            string to test
     * @return <code>true</code> if the string is empty or null; <code>false</code> otherwise
     */
    public static boolean isEmpty(final String value) {
        return value == null || value.trim().length() == 0;
    }

}
