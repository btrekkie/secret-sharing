package com.github.btrekkie.secret_sharing;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * NEVER USE THIS. I am not a cryptography specialist. You should only use cryptographic functions that were implemented
 * by a specialist in cryptography and have been carefully vetted and tested. Otherwise, they are liable to have
 * vulnerabilities. This library is subject to timing attacks. This software is purely for instructional purposes.
 *
 * -----
 *
 * A group from which secret shares may be drawn. See the comments for SecretSharing.
 *
 * Each SecretShareGroup stores a secret and contains a large number of secret shares, any sharesNeeded of which may be
 * used to reconstruct the secret. Each of the group's shares is associated with a "share number," which is an integer
 * from 0 to the larger of Integer.MAX_VALUE and 2 ^ (8 * secret.length) - 1.
 *
 * Every SecretShareGroup produced by a separate call to createFromSecret (or implicitly produced by a separate call to
 * SecretSharing.splitSecret) is completely independent of every other one, even if they have the same secret. Shares
 * from different SecretShareGroups cannot be mixed and matched to reconstruct a secret. This is not simply a limitation
 * of this library. In the same way that possession of sharesNeeded - 1 secret shares provides no information about the
 * secret (see the comments for SecretSharing for details), possession of sharesNeeded - 1 secret shares from each of an
 * arbitrarily large number of SecretShareGroups also provides no information. For example, if sharesNeeded is 3, then
 * possession of two shares from each of 1000 SecretShareGroups with the same secret - 2000 shares in total - provides
 * no information about the secret.
 */
public class SecretShareGroup {
    /** The group's parameters. */
    private final SecretShareGroupParams params;

    /**
     * The coefficients for the polynomial this group uses to generate secret shares. coefficients[0] is equal to
     * SecretSharingUtil.encodeSecret(secret). The other elements are random integers from 0 to params.modulus - 1. The
     * polynomial is coefficients[0] + coefficients[1] * x + coefficients[2] * x * x + ... (mod params.modulus).
     */
    private final BigInteger[] coefficients;

    SecretShareGroup(SecretShareGroupParams params, BigInteger[] coefficients) {
        this.params = params;
        this.coefficients = coefficients;
    }

    /**
     * Returns a new SecretShareGroup for obtaining shares of the specified secret.
     * @param secret The secret.
     * @param sharesNeeded The number of shares needed to reconstruct the secret.
     * @param random The SecureRandom instance to use as the source of randomness.
     * @return The SecretShareGroup.
     * @throws IllegalArgumentException If sharesNeeded <= 0.
     */
    public static SecretShareGroup createFromSecret(byte[] secret, int sharesNeeded, SecureRandom random) {
        if (sharesNeeded <= 0) {
            throw new IllegalArgumentException("sharesNeeded must be positive");
        }
        if (secret.length > SecretSharingUtil.MAX_SECRET_LENGTH) {
            throw new IllegalArgumentException("The maximum allowed secret length is 2^28 - 1 bytes");
        }

        SecretShareGroupParams params = new SecretShareGroupParams(sharesNeeded, secret.length, random.nextInt());
        BigInteger[] coefficients = new BigInteger[sharesNeeded];
        coefficients[0] = SecretSharingUtil.encodeSecret(secret);
        for (int i = 1; i < sharesNeeded; i++) {
            do {
                coefficients[i] = new BigInteger(params.modulus.bitLength(), random);
            } while (coefficients[i].compareTo(params.modulus) >= 0);
        }
        return new SecretShareGroup(params, coefficients);
    }

    /**
     * Returns a new SecretShareGroup for obtaining shares of the specified secret.
     * @param secret The secret.
     * @param sharesNeeded The number of shares needed to reconstruct the secret.
     * @return The SecretShareGroup.
     * @throws IllegalArgumentException If sharesNeeded <= 0.
     */
    public static SecretShareGroup createFromSecret(byte[] secret, int sharesNeeded) {
        return createFromSecret(secret, sharesNeeded, new SecureRandom());
    }

    /**
     * Returns the share with the specified number.
     * @param shareNumber The share number.
     * @return The share.
     * @throws IllegalArgumentException If shareNumber is negative or is greater than both Integer.MAX_VALUE and
     *     2 ^ (8 * secret.length) - 1.
     */
    public SecretShare share(BigInteger shareNumber) {
        if (shareNumber.signum() == -1) {
            throw new IllegalArgumentException("shareNumber may not be negative");
        }
        if (shareNumber.bitLength() > SecretSharingUtil.groupBits(params.secretLength)) {
            throw new IllegalArgumentException("shareNumber is too large");
        }

        BigInteger x = shareNumber.add(BigInteger.ONE);
        BigInteger y = BigInteger.ZERO;
        BigInteger power = BigInteger.ONE;
        for (BigInteger coefficient : coefficients) {
            y = y.add(coefficient.multiply(power).mod(params.modulus)).mod(params.modulus);
            power = power.multiply(x).mod(params.modulus);
        }
        return new SecretShare(params, x, y);
    }

    /**
     * Returns the share with the specified number.
     * @param shareNumber The share number.
     * @return The share.
     * @throws IllegalArgumentException If shareNumber is negative.
     */
    public SecretShare share(int shareNumber) {
        return share(BigInteger.valueOf(shareNumber));
    }

    /** Returns the secret for this group. */
    public byte[] secret() {
        return SecretSharingUtil.decodeSecret(coefficients[0], params.secretLength);
    }

    /** Returns the number of shares needed to reconstruct the secret. */
    public int sharesNeeded() {
        return params.sharesNeeded;
    }

    /** Returns a byte array encoding this group. This is the inverse of createFromBytes. */
    public byte[] toBytes() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            params.write(output);
            for (BigInteger coefficient : coefficients) {
                SecretSharingUtil.writeNonnegativeBigInteger(output, coefficient);
            }
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
        return output.toByteArray();
    }

    /**
     * Returns the group encoded by the specified byte array. This is the inverse of toBytes().
     * @param bytes The byte array.
     * @return The group.
     * @throws IllegalArgumentException If we detect that the specified byte array is not a valid encoding of a
     *     SecretShareGroup.
     */
    public static SecretShareGroup createFromBytes(byte[] bytes) {
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        SecretShareGroupParams params;
        BigInteger[] coefficients;
        try {
            params = SecretShareGroupParams.read(input);
            coefficients = new BigInteger[params.sharesNeeded];
            for (int i = 0; i < params.sharesNeeded; i++) {
                coefficients[i] = SecretSharingUtil.readNonnegativeBigInteger(input);
            }
        } catch (IOException exception) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }

        if (input.available() > 0 || coefficients[0].bitLength() > 8 * params.secretLength) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        for (int i = 1; i < coefficients.length; i++) {
            if (coefficients[i].compareTo(params.modulus) >= 0) {
                throw new IllegalArgumentException("Invalid byte encoding");
            }
        }
        return new SecretShareGroup(params, coefficients);
    }
}
