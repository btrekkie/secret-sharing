package com.github.btrekkie.secret_sharing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

/**
 * NEVER USE THIS. I am not a cryptography specialist. You should only use cryptographic functions that were implemented
 * by a specialist in cryptography and have been carefully vetted and tested. Otherwise, they are liable to have
 * vulnerabilities. This library is subject to timing attacks. This software is purely for instructional purposes.
 *
 * -----
 *
 * Provides static methods used in different parts of the library.
 */
class SecretSharingUtil {
    /**
     * The maximum number of bytes in a secret. We limit this to 2 ^ 28 - 1 for convenience of implementation. This
     * makes it easier to compute 2 ^ (8 * secretLength) in order to calculate an appropriate modulus.
     */
    public static final int MAX_SECRET_LENGTH = 0x0fffffff;

    /**
     * Returns log base 2 of the number of shares in a SecretShareGroup whose secret has the specified number of bytes.
     */
    public static int groupBits(int secretLength) {
        return Math.max(31, 8 * secretLength);
    }

    /**
     * Throws in IllegalArgumentException if we are able to detect that the specified shares are invalid. There must be
     * shareNumber shares (or shareNumber - 1 if haveSecret is true), including at least one share. They must all be
     * distinct and belong to the same SecretShareGroup.
     */
    public static void checkShares(SecretShare[] shares, boolean haveSecret) {
        if (shares.length == 0) {
            throw new IllegalArgumentException("There must be at least one SecretShare");
        }

        SecretShareGroupParams params = shares[0].params;
        for (int i = 1; i < shares.length; i++) {
            if (!shares[i].params.equals(params)) {
                throw new IllegalArgumentException(
                    "The specified SecretShares do not belong to the same SecretShareGroup");
            }
        }

        if (haveSecret) {
            if (shares.length != params.sharesNeeded - 1) {
                throw new IllegalArgumentException(
                    "There must be exactly " + (params.sharesNeeded - 1) + " shares (one less than the number of " +
                    "shares in the secret share group)");
            }
        } else if (shares.length != params.sharesNeeded) {
            throw new IllegalArgumentException(
                "There must be exactly " + params.sharesNeeded + " shares (the number of shares in the secret share " +
                "group)");
        }

        Set<BigInteger> xs = new HashSet<BigInteger>();
        for (SecretShare share : shares) {
            if (!xs.add(share.x)) {
                throw new IllegalArgumentException("The specified SecretShares must all be unique");
            }
        }
    }

    /** Equivalent implementation is contractually guaranteed. */
    public static void checkShares(SecretShare[] shares) {
        checkShares(shares, false);
    }

    /**
     * Returns the BigInteger encoding of the specified secret. This is the value obtained by reading the secret as a
     * big-endian unsigned integer. This is the inverse of decodeSecret.
     */
    public static BigInteger encodeSecret(byte[] secret) {
        return new BigInteger(1, secret);
    }

    /**
     * Returns the secret encoded in the specified BigInteger. This is the big-endian unsigned integer representation of
     * "value". This is the inverse of encodeSecret.
     * @param value The value to decode.
     * @param secretLength The number of bytes in the secret.
     * @return The secret.
     */
    public static byte[] decodeSecret(BigInteger value, int secretLength) {
        // In order to ensure correct alignment of the bits, we pad "value" with the appropriate power of 2
        int minBits = Math.max(8 * secretLength, value.bitLength());
        BigInteger padding = BigInteger.ONE.shiftLeft(minBits + 6 - (minBits % 8));
        byte[] paddedBytes = value.or(padding).toByteArray();
        byte[] bytes = new byte[secretLength];
        System.arraycopy(paddedBytes, paddedBytes.length - secretLength, bytes, 0, secretLength);
        return bytes;
    }

    /**
     * Writes the specified integer to "output". This is the inverse of readInt.
     * @param output The output stream.
     * @param value The value to write.
     * @throws IOException If "output" throws an IOException.
     */
    public static void writeInt(OutputStream output, int value) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(value);
        output.write(buffer.array());
    }

    /**
     * Reads an integer from the specified input stream. This is the inverse of writeInt.
     * @param input The input stream.
     * @return The value we read.
     * @throws IOException If "input" throws an IOException.
     * @throws IllegalArgumentException If the input stream does not contain a valid encoding of an integer.
     */
    public static int readInt(InputStream input) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        if (input.read(buffer.array()) < 4) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        return buffer.getInt(0);
    }

    /**
     * Writes the specified nonnegative BigInteger to "output". The encoding is shorter for smaller integers. This is
     * the inverse of readNonnegativeBigInteger.
     * @param output The output stream.
     * @param value The value to write.
     * @throws IOException If "output" throws an IOException.
     */
    public static void writeNonnegativeBigInteger(OutputStream output, BigInteger value) throws IOException {
        if (value.bitLength() <= 31) {
            writeInt(output, value.intValue());
        } else {
            // In order to ensure correct alignment of the bits, we pad "value" with the appropriate power of 2
            int bitLength = value.bitLength();
            BigInteger padding = BigInteger.ONE.shiftLeft(bitLength + 14 - (bitLength % 8));
            byte[] bytes = value.or(padding).toByteArray();
            writeInt(output, 0x80000000 | (bytes.length - 1));
            output.write(bytes, 1, bytes.length - 1);
        }
    }

    /**
     * Reads a nonnegative BigInteger from the specified input stream. This is the inverse of
     * writeNonnegativeBigInteger.
     * @param input The input stream.
     * @return The value we read.
     * @throws IOException If "input" throws an IOException.
     * @throws IllegalArgumentException If the input stream does not contain a valid encoding of a nonnegative
     *     BigInteger.
     */
    public static BigInteger readNonnegativeBigInteger(InputStream input) throws IOException {
        int intValue = readInt(input);
        if ((intValue & 0x80000000) == 0) {
            return BigInteger.valueOf(intValue);
        } else {
            int length = intValue & 0x7fffffff;
            byte[] bytes = new byte[length];
            if (input.read(bytes) < length) {
                throw new IllegalArgumentException("Invalid byte encoding");
            }
            return new BigInteger(1, bytes);
        }
    }
}
