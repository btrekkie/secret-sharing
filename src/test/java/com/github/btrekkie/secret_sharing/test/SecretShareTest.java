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

public class SecretShareTest {
    /**
     * A random number generator to use for testing. This uses a fixed value for the initial seed, so that test failures
     * are reproducible.
     */
    private final SecureRandom random = new SecureRandom(new byte[]{51, -77, -55, 101, 81, -80, 94, -116});

    /** Tests the accessor methods, shareNumber(), bigShareNumber(), sharesNeeded(), and secretLength(). */
    @Test
    public void testAccessors() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret1, 3, random);
        SecretShare share1a = group1.share(0);
        assertEquals(0, share1a.shareNumber());
        assertEquals(BigInteger.ZERO, share1a.bigShareNumber());
        assertEquals(3, share1a.sharesNeeded());
        assertEquals(38, share1a.secretLength());

        SecretShare share1b = group1.share(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, share1b.shareNumber());
        assertEquals(BigInteger.valueOf(Integer.MAX_VALUE), share1b.bigShareNumber());
        assertEquals(3, share1b.sharesNeeded());
        assertEquals(38, share1b.secretLength());

        BigInteger shareNumber = BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE);
        SecretShare share1c = group1.share(shareNumber);
        assertEquals(shareNumber, share1c.bigShareNumber());
        assertEquals(3, share1c.sharesNeeded());
        assertEquals(38, share1c.secretLength());

        byte[] secret2 = new byte[0];
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(secret2, 1, random);
        SecretShare share2a = group2.share(42);
        assertEquals(42, share2a.shareNumber());
        assertEquals(BigInteger.valueOf(42), share2a.bigShareNumber());
        assertEquals(1, share2a.sharesNeeded());
        assertEquals(0, share2a.secretLength());

        SecretShare share2b = group2.share(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, share2b.shareNumber());
        assertEquals(BigInteger.valueOf(Integer.MAX_VALUE), share2b.bigShareNumber());
        assertEquals(1, share2b.sharesNeeded());
        assertEquals(0, share2b.secretLength());
    }

    /** Tests the serialization methods toBytes() and createFromBytes. */
    @Test
    public void testSerialization() {
        byte[] secret = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretShare share = SecretShare.createFromBytes(group.share(42).toBytes());
        assertEquals(42, share.shareNumber());
        assertEquals(3, share.sharesNeeded());
        assertEquals(38, share.secretLength());
        assertTrue(
            Arrays.equals(
                secret,
                SecretSharing.reconstructSecret(
                    new SecretShare[]{
                        group.share(0), share, group.share(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE))})));
    }

    /**
     * Tests the serialization methods toBytes() and createFromBytes by attempting to reconstruct a secret from
     * SecretShares from different groups.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSerializationMismatch() {
        byte[] secret = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(secret, 2, random);
        SecretShare share = SecretShare.createFromBytes(group2.share(1).toBytes());
        SecretSharing.reconstructSecret(new SecretShare[]{group1.share(0), share, group1.share(2)});
    }

    /** Tests calling shareNumber() when the share number is greater than Integer.MAX_VALUE. */
    @Test(expected = RuntimeException.class)
    public void testShareNumberTooGreat() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 3, random);
        group.share(BigInteger.valueOf(0x80000000L)).shareNumber();
    }
}
