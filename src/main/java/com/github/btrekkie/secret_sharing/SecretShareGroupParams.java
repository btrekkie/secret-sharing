package com.github.btrekkie.secret_sharing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * NEVER USE THIS. I am not a cryptography specialist. You should only use cryptographic functions that were implemented
 * by a specialist in cryptography and have been carefully vetted and tested. Otherwise, they are liable to have
 * vulnerabilities. This library is subject to timing attacks. This software is purely for instructional purposes.
 *
 * -----
 *
 * The parameters for a SecretShareGroup. This contains all of the information about the group that is not meant to be
 * kept secret - i.e. everything except the polynomial's coefficients. Every SecretShare stores the
 * SecretShareGroupParams of the group that contains it.
 */
class SecretShareGroupParams {
    /**
     * A lookup table for "modulus". This contains a map from some common values for X to the (positive) difference
     * between 2 ^ X and the smallest prime greater than 2 ^ X.
     */
    private static final Map<Integer, Integer> modulusLookup = new HashMap<Integer, Integer>();

    /**
     * The prime modulus for the polynomial that the group uses to generate secret shares. This is greater than
     * 2 ^ SecretSharingUtil.groupBits(secretLength).
     */
    public final BigInteger modulus;

    /** Returns the number of shares needed to reconstruct the secret. */
    public final int sharesNeeded;

    /** Returns the number of bytes in the secret. */
    public final int secretLength;

    /**
     * A random integer identifying the group. We can use the ID to check whether two SecretShares belong to the same
     * group, although false positives are possible. Such a check guards against accidentally trying to reconstruct a
     * secret using shares from different groups.
     */
    public final int id;

    static {
        modulusLookup.put(31, 11);
        modulusLookup.put(32, 15);
        modulusLookup.put(64, 13);
        modulusLookup.put(128, 51);
        modulusLookup.put(256, 297);
        modulusLookup.put(512, 75);
        modulusLookup.put(1024, 643);
        modulusLookup.put(2048, 981);
        modulusLookup.put(4096, 1761);
        modulusLookup.put(8192, 897);
        modulusLookup.put(16384, 2775);
    }

    public SecretShareGroupParams(int sharesNeeded, int secretLength, int id) {
        this.sharesNeeded = sharesNeeded;
        this.secretLength = secretLength;
        this.id = id;

        // Set "modulus" to be the smallest prime number greater than 2 ^ SecretSharingUtil.groupBits(secretLength). Any
        // prime number greater than this will do, but a smaller modulus results in a smaller byte array encoding.
        int groupBits = SecretSharingUtil.groupBits(secretLength);
        Integer lookup = modulusLookup.get(groupBits);
        if (lookup == null) {
            modulus = BigInteger.ONE.shiftLeft(groupBits).nextProbablePrime();
        } else {
            modulus = BigInteger.ONE.shiftLeft(groupBits).add(BigInteger.valueOf(lookup));
        }
    }

    private SecretShareGroupParams(int sharesNeeded, int secretLength, int id, BigInteger modulus) {
        this.sharesNeeded = sharesNeeded;
        this.secretLength = secretLength;
        this.id = id;
        this.modulus = modulus;
    }

    /**
     * Writes a byte array encoding of these parameters to "output". This is the inverse of "read".
     * @param output The output stream.
     * @throws IOException If "output" throws an IOException.
     */
    public void write(OutputStream output) throws IOException {
        SecretSharingUtil.writeInt(output, sharesNeeded);
        SecretSharingUtil.writeInt(output, secretLength);
        SecretSharingUtil.writeInt(output, id);
        int groupBits = SecretSharingUtil.groupBits(secretLength);
        SecretSharingUtil.writeNonnegativeBigInteger(output, modulus.subtract(BigInteger.ONE.shiftLeft(groupBits)));
    }

    /**
     * Reads a SecretShareGroupParams object from the specified input stream. This is the inverse of "write".
     * @param input The input stream.
     * @return The parameters.
     * @throws IOException If "input" throws an IOException.
     * @throws IllegalArgumentException If we detect that the input stream does not contain a valid encoding of a
     *     SecretShareGroupParams object.
     */
    public static SecretShareGroupParams read(InputStream input) throws IOException {
        int sharesNeeded = SecretSharingUtil.readInt(input);
        if (sharesNeeded <= 0) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        int secretLength = SecretSharingUtil.readInt(input);
        if (secretLength < 0 || secretLength > SecretSharingUtil.MAX_SECRET_LENGTH) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        int id = SecretSharingUtil.readInt(input);

        int groupBits = SecretSharingUtil.groupBits(secretLength);
        BigInteger modulus =
            BigInteger.ONE.shiftLeft(groupBits).add(SecretSharingUtil.readNonnegativeBigInteger(input));
        return new SecretShareGroupParams(sharesNeeded, secretLength, id, modulus);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof SecretShareGroupParams)) {
            return false;
        }
        SecretShareGroupParams params = (SecretShareGroupParams)obj;
        return id == params.id && sharesNeeded == params.sharesNeeded && secretLength == params.secretLength &&
            modulus.equals(params.modulus);
    }
}
