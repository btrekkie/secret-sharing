package com.github.btrekkie.secret_sharing;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * NEVER USE THIS. I am not a cryptography specialist. You should only use cryptographic functions that were implemented
 * by a specialist in cryptography and have been carefully vetted and tested. Otherwise, they are liable to have
 * vulnerabilities. This library is subject to timing attacks. This software is purely for instructional purposes.
 *
 * -----
 *
 * A secret share. See the comments for SecretSharing.
 *
 * SecretShares may be combined to recover a secret. Each SecretShare stores the number of bytes in the secret.
 */
public class SecretShare {
    /** The parameters for the SecretShareGroup that this belongs to. */
    final SecretShareGroupParams params;

    /**
     * The x coordinate of the point on the polynomial that this SecretShare stores. The polynomial is given by
     * G.coefficients, where G is the SecretShareGroup that this belongs to. The x coordinate is equal to the share
     * number plus one.
     */
    final BigInteger x;

    /**
     * The y coordinate of the point on the polynomial that this SecretShare stores. The polynomial is given by
     * G.coefficients, where G is the SecretShareGroup that this belongs to.
     */
    final BigInteger y;

    SecretShare(SecretShareGroupParams params, BigInteger x, BigInteger y) {
        this.params = params;
        this.x = x;
        this.y = y;
    }

    /** Returns the share number of this share in the SecretShareGroup that this belongs to. */
    public BigInteger bigShareNumber() {
        return x.subtract(BigInteger.ONE);
    }

    /**
     * Returns the share number of this share in the SecretShareGroup that this belongs to.
     * @throws RuntimeException If the share number is greater than Integer.MAX_VALUE. If the share number might be
     *     greater than Integer.MAX_VALUE, then you should call bigShareNumber() instead.
     */
    public int shareNumber() {
        BigInteger shareNumber = bigShareNumber();
        if (shareNumber.bitLength() > 31) {
            throw new RuntimeException(
                "The share number is larger than 2^31 - 1. It must be obtained using bigShareNumber().");
        }
        return shareNumber.intValue();
    }

    /** Returns the number of shares needed to reconstruct the secret. */
    public int sharesNeeded() {
        return params.sharesNeeded;
    }

    /** Returns the number of bytes in the secret. */
    public int secretLength() {
        return params.secretLength;
    }

    /** Returns a byte array encoding this share. This is the inverse of createFromBytes. */
    public byte[] toBytes() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            params.write(output);
            SecretSharingUtil.writeNonnegativeBigInteger(output, x);
            SecretSharingUtil.writeNonnegativeBigInteger(output, y);
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
        return output.toByteArray();
    }

    /**
     * Returns the share encoded by the specified byte array. This is the inverse of toBytes().
     * @param bytes The byte array.
     * @return The share.
     * @throws IllegalArgumentException If we detect that the specified byte array is not a valid encoding of a
     *     SecretShare.
     */
    public static SecretShare createFromBytes(byte[] bytes) {
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        SecretShareGroupParams params;
        BigInteger x;
        BigInteger y;
        try {
            params = SecretShareGroupParams.read(input);
            x = SecretSharingUtil.readNonnegativeBigInteger(input);
            y = SecretSharingUtil.readNonnegativeBigInteger(input);
        } catch (IOException exception) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        if (input.available() > 0 || x.equals(BigInteger.ZERO) || x.compareTo(params.modulus) >= 0 ||
                y.compareTo(params.modulus) >= 0) {
            throw new IllegalArgumentException("Invalid byte encoding");
        }
        return new SecretShare(params, x, y);
    }
}
