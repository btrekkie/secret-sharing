package com.github.btrekkie.secret_sharing.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

import com.github.btrekkie.secret_sharing.SecretShare;
import com.github.btrekkie.secret_sharing.SecretShareGroup;
import com.github.btrekkie.secret_sharing.SecretSharing;

public class SecretShareGroupTest {
    /**
     * A random number generator to use for testing. This uses a fixed value for the initial seed, so that test failures
     * are reproducible.
     */
    private final SecureRandom random = new SecureRandom(new byte[]{51, -77, -55, 101, 81, -80, 94, -116});

    /** Tests the accessor methods, secret() and sharesNeeded(). */
    @Test
    public void testAccessors() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret1, 3, random);
        assertTrue(Arrays.equals(secret1, group1.secret()));
        assertEquals(3, group1.sharesNeeded());

        byte[] secret2 = new byte[0];
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(secret2, 1, random);
        assertTrue(Arrays.equals(secret2, group2.secret()));
        assertEquals(1, group2.sharesNeeded());
    }

    /** Tests the serialization methods toBytes() and createFromBytes. */
    @Test
    public void testSerialization() {
        byte[] secret = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretShareGroup group2 = SecretShareGroup.createFromBytes(group1.toBytes());
        assertTrue(Arrays.equals(secret, group2.secret()));
        assertEquals(3, group2.sharesNeeded());
        assertTrue(
            Arrays.equals(
                SecretSharing.reconstructSecret(
                    new SecretShare[]{
                        group1.share(0), group2.share(1), group1.share(BigInteger.valueOf(17).shiftLeft(256))}),
                secret));
    }

    /**
     * Tests the serialization methods toBytes() and createFromBytes by attempting to reconstruct a secret from
     * SecretShares from different groups.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSerializationMismatch() {
        byte[] secret = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretShareGroup group2 = SecretShareGroup.createFromBytes(group1.toBytes());
        SecretShareGroup group3 = SecretShareGroup.createFromSecret(secret, 2, random);
        SecretSharing.reconstructSecret(new SecretShare[]{group2.share(0), group3.share(1), group2.share(2)});
    }

    /** Tests SecretShareGroup.createFromSecret where sharesNeeded is 0. */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateZeroSharesNeeded() {
        SecretShareGroup.createFromSecret(new byte[32], 0, random);
    }

    /** Tests SecretShareGroup.createFromSecret where sharesNeeded is negative. */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateNegativeSharesNeeded() {
        SecretShareGroup.createFromSecret(new byte[32], -2, random);
    }

    /** Tests SecretShareGroup.share where the share number is negative. */
    @Test(expected = IllegalArgumentException.class)
    public void testNegativeShareNumber() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        group.share(-1);
    }

    /** Tests SecretShareGroup.share where the share number is too large and the secret is shorter than 4 bytes. */
    @Test(expected = IllegalArgumentException.class)
    public void testShareNumberTooGreatShortSecret() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[1], 2, random);
        group.share(BigInteger.valueOf(0x80000000L));
    }

    /**
     * Tests SecretShareGroup.share where the share number is too large and the secret is at least 4 bytes in length.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testShareNumberTooGreatLongSecret() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        group.share(BigInteger.ONE.shiftLeft(256));
    }
}
