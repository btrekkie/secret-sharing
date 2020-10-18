package com.github.btrekkie.secret_sharing.test;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

import com.github.btrekkie.secret_sharing.SecretShare;
import com.github.btrekkie.secret_sharing.SecretShareGroup;
import com.github.btrekkie.secret_sharing.SecretSharing;

public class SecretSharingTest {
    /**
     * A random number generator to use for testing. This uses a fixed value for the initial seed, so that test failures
     * are reproducible.
     */
    private final SecureRandom random = new SecureRandom(new byte[]{51, -77, -55, 101, 81, -80, 94, -116});

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) using shares obtained with SecretShareGroup.share. */
    @Test
    public void testReconstructSecretFromGroup() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret1, 3, random);
        SecretShare[] shares1 = new SecretShare[]{
            group1.share(0), group1.share(7), group1.share(Integer.MAX_VALUE),
            group1.share(BigInteger.valueOf(3).shiftLeft(80)),
            group1.share(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE))};
        assertTrue(
            Arrays.equals(
                secret1, SecretSharing.reconstructSecret(new SecretShare[]{shares1[0], shares1[1], shares1[2]})));
        assertTrue(
            Arrays.equals(
                secret1, SecretSharing.reconstructSecret(new SecretShare[]{shares1[2], shares1[3], shares1[4]})));
        assertTrue(
            Arrays.equals(
                secret1, SecretSharing.reconstructSecret(new SecretShare[]{shares1[4], shares1[2], shares1[0]})));

        byte[] secret2 = "Lorem ipsum dolor sit amet, cons".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(secret2, 3, random);
        SecretShare[] shares2 = new SecretShare[]{
            group2.share(0), group2.share(7), group2.share(Integer.MAX_VALUE),
            group2.share(BigInteger.valueOf(3).shiftLeft(80)),
            group2.share(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))};
        assertTrue(
            Arrays.equals(
                secret2, SecretSharing.reconstructSecret(new SecretShare[]{shares2[0], shares2[1], shares2[2]})));
        assertTrue(
            Arrays.equals(
                secret2, SecretSharing.reconstructSecret(new SecretShare[]{shares2[2], shares2[3], shares2[4]})));
        assertTrue(
            Arrays.equals(
                secret2, SecretSharing.reconstructSecret(new SecretShare[]{shares2[0], shares2[2], shares2[4]})));

        byte[] secret3 = "L".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group3 = SecretShareGroup.createFromSecret(secret3, 2, random);
        SecretShare[] shares3 = new SecretShare[]{
            group3.share(0), group3.share(1), group3.share(5), group3.share(12345), group3.share(Integer.MAX_VALUE)};
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new SecretShare[]{shares3[0], shares3[1]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new SecretShare[]{shares3[2], shares3[3]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new SecretShare[]{shares3[1], shares3[4]})));

        byte[] secret4 = new byte[2];
        SecretShareGroup group4 = SecretShareGroup.createFromSecret(secret4, 3, random);
        SecretShare[] shares4 = new SecretShare[]{
            group4.share(0), group4.share(1), group4.share(5), group4.share(12345), group4.share(Integer.MAX_VALUE)};
        assertTrue(
            Arrays.equals(
                secret4, SecretSharing.reconstructSecret(new SecretShare[]{shares4[0], shares4[1], shares4[2]})));
        assertTrue(
            Arrays.equals(
                secret4, SecretSharing.reconstructSecret(new SecretShare[]{shares4[2], shares4[3], shares4[4]})));
        assertTrue(
            Arrays.equals(
                secret4, SecretSharing.reconstructSecret(new SecretShare[]{shares4[0], shares4[2], shares4[4]})));

        byte[] secret5 = new byte[64];
        SecretShareGroup group5 = SecretShareGroup.createFromSecret(secret5, 3, random);
        SecretShare[] shares5 = new SecretShare[]{
            group5.share(0), group5.share(7), group5.share(Integer.MAX_VALUE),
            group5.share(BigInteger.valueOf(3).shiftLeft(80)),
            group5.share(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))};
        assertTrue(
            Arrays.equals(
                secret5, SecretSharing.reconstructSecret(new SecretShare[]{shares5[0], shares5[1], shares5[2]})));
        assertTrue(
            Arrays.equals(
                secret5, SecretSharing.reconstructSecret(new SecretShare[]{shares5[2], shares5[3], shares5[4]})));
        assertTrue(
            Arrays.equals(
                secret5, SecretSharing.reconstructSecret(new SecretShare[]{shares5[0], shares5[2], shares5[4]})));

        byte[] secret6 = new byte[32];
        for (int i = 0; i < 32; i++) {
            secret6[i] = (byte)0xff;
        }
        SecretShareGroup group6 = SecretShareGroup.createFromSecret(secret6, 3, random);
        SecretShare[] shares6 = new SecretShare[]{
            group6.share(0), group6.share(7), group6.share(Integer.MAX_VALUE),
            group6.share(BigInteger.valueOf(3).shiftLeft(80)),
            group6.share(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))};
        assertTrue(
            Arrays.equals(
                secret6, SecretSharing.reconstructSecret(new SecretShare[]{shares6[0], shares6[1], shares6[2]})));
        assertTrue(
            Arrays.equals(
                secret6, SecretSharing.reconstructSecret(new SecretShare[]{shares6[2], shares6[3], shares6[4]})));
        assertTrue(
            Arrays.equals(
                secret6, SecretSharing.reconstructSecret(new SecretShare[]{shares6[0], shares6[2], shares6[4]})));

        byte[] secret7 = new byte[0];
        SecretShareGroup group7 = SecretShareGroup.createFromSecret(secret7, 4, random);
        SecretShare[] shares7 = new SecretShare[]{
            group7.share(0), group7.share(1), group7.share(5), group7.share(12345), group7.share(6789),
            group7.share(Integer.MAX_VALUE)};
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new SecretShare[]{shares7[0], shares7[1], shares7[2], shares7[3]})));
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new SecretShare[]{shares7[2], shares7[3], shares7[4], shares7[5]})));

        byte[] secret8 = "Lorem ipsum dolor".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group8 = SecretShareGroup.createFromSecret(secret8, 1, random);
        SecretShare[] shares8 = new SecretShare[]{
            group8.share(0), group8.share(Integer.MAX_VALUE),
            group8.share(BigInteger.ONE.shiftLeft(136).subtract(BigInteger.ONE))};
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new SecretShare[]{shares8[0]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new SecretShare[]{shares8[1]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new SecretShare[]{shares8[2]})));
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) using shares obtained with SecretSharing.splitSecret. */
    @Test
    public void testReconstructSecretFromBytes() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        byte[][] shares1 = SecretSharing.splitSecret(secret1, 3, 5, random);
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[0], shares1[1], shares1[2]})));
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[2], shares1[3], shares1[4]})));
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[4], shares1[2], shares1[0]})));

        byte[] secret2 = "Lorem ipsum dolor sit amet, cons".getBytes(StandardCharsets.US_ASCII);
        byte[][] shares2 = SecretSharing.splitSecret(secret2, 3, 5, random);
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[0], shares2[1], shares2[2]})));
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[2], shares2[3], shares2[4]})));
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[0], shares2[2], shares2[4]})));

        byte[] secret3 = "L".getBytes(StandardCharsets.US_ASCII);
        byte[][] shares3 = SecretSharing.splitSecret(secret3, 2, 5, random);
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[0], shares3[1]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[2], shares3[3]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[1], shares3[4]})));

        byte[] secret4 = new byte[2];
        byte[][] shares4 = SecretSharing.splitSecret(secret4, 3, 5, random);
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[0], shares4[1], shares4[2]})));
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[2], shares4[3], shares4[4]})));
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[0], shares4[2], shares4[4]})));

        byte[] secret5 = new byte[64];
        byte[][] shares5 = SecretSharing.splitSecret(secret5, 3, 5, random);
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[0], shares5[1], shares5[2]})));
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[2], shares5[3], shares5[4]})));
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[0], shares5[2], shares5[4]})));

        byte[] secret6 = new byte[32];
        for (int i = 0; i < 32; i++) {
            secret6[i] = (byte)0xff;
        }
        byte[][] shares6 = SecretSharing.splitSecret(secret6, 3, 3, random);
        assertTrue(Arrays.equals(secret6, SecretSharing.reconstructSecret(shares6)));

        byte[] secret7 = new byte[0];
        byte[][] shares7 = SecretSharing.splitSecret(secret7, 4, 6, random);
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new byte[][]{shares7[0], shares7[1], shares7[2], shares7[3]})));
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new byte[][]{shares7[2], shares7[3], shares7[4], shares7[5]})));

        byte[] secret8 = "Lorem ipsum dolor".getBytes(StandardCharsets.US_ASCII);
        byte[][] shares8 = SecretSharing.splitSecret(secret8, 1, 3, random);
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[0]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[1]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[2]})));
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) using shares obtained with SecretShareGroup.share.toBytes(). */
    @Test
    public void testReconstructSecretFromGroupBytes() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret1, 3, random);
        byte[][] shares1 = new byte[][]{
            group1.share(0).toBytes(), group1.share(7).toBytes(), group1.share(Integer.MAX_VALUE).toBytes(),
            group1.share(BigInteger.valueOf(3).shiftLeft(80)).toBytes(),
            group1.share(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE)).toBytes()};
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[0], shares1[1], shares1[2]})));
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[2], shares1[3], shares1[4]})));
        assertTrue(
            Arrays.equals(secret1, SecretSharing.reconstructSecret(new byte[][]{shares1[4], shares1[2], shares1[0]})));

        byte[] secret2 = "Lorem ipsum dolor sit amet, cons".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(secret2, 3, random);
        byte[][] shares2 = new byte[][]{
            group2.share(0).toBytes(), group2.share(7).toBytes(), group2.share(Integer.MAX_VALUE).toBytes(),
            group2.share(BigInteger.valueOf(3).shiftLeft(80)).toBytes(),
            group2.share(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)).toBytes()};
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[0], shares2[1], shares2[2]})));
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[2], shares2[3], shares2[4]})));
        assertTrue(
            Arrays.equals(secret2, SecretSharing.reconstructSecret(new byte[][]{shares2[0], shares2[2], shares2[4]})));

        byte[] secret3 = "L".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group3 = SecretShareGroup.createFromSecret(secret3, 2, random);
        byte[][] shares3 = new byte[][]{
            group3.share(0).toBytes(), group3.share(1).toBytes(), group3.share(5).toBytes(),
            group3.share(12345).toBytes(), group3.share(Integer.MAX_VALUE).toBytes()};
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[0], shares3[1]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[2], shares3[3]})));
        assertTrue(
            Arrays.equals(secret3, SecretSharing.reconstructSecret(new byte[][]{shares3[1], shares3[4]})));

        byte[] secret4 = new byte[2];
        SecretShareGroup group4 = SecretShareGroup.createFromSecret(secret4, 3, random);
        byte[][] shares4 = new byte[][]{
            group4.share(0).toBytes(), group4.share(1).toBytes(), group4.share(5).toBytes(),
            group4.share(12345).toBytes(), group4.share(Integer.MAX_VALUE).toBytes()};
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[0], shares4[1], shares4[2]})));
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[2], shares4[3], shares4[4]})));
        assertTrue(
            Arrays.equals(secret4, SecretSharing.reconstructSecret(new byte[][]{shares4[0], shares4[2], shares4[4]})));

        byte[] secret5 = new byte[64];
        SecretShareGroup group5 = SecretShareGroup.createFromSecret(secret5, 3, random);
        byte[][] shares5 = new byte[][]{
            group5.share(0).toBytes(), group5.share(7).toBytes(), group5.share(Integer.MAX_VALUE).toBytes(),
            group5.share(BigInteger.valueOf(3).shiftLeft(80)).toBytes(),
            group5.share(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)).toBytes()};
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[0], shares5[1], shares5[2]})));
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[2], shares5[3], shares5[4]})));
        assertTrue(
            Arrays.equals(secret5, SecretSharing.reconstructSecret(new byte[][]{shares5[0], shares5[2], shares5[4]})));

        byte[] secret6 = new byte[32];
        for (int i = 0; i < 32; i++) {
            secret6[i] = (byte)0xff;
        }
        SecretShareGroup group6 = SecretShareGroup.createFromSecret(secret6, 3, random);
        byte[][] shares6 = new byte[][]{
            group6.share(0).toBytes(), group6.share(7).toBytes(), group6.share(Integer.MAX_VALUE).toBytes(),
            group6.share(BigInteger.valueOf(3).shiftLeft(80)).toBytes(),
            group6.share(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)).toBytes()};
        assertTrue(
            Arrays.equals(secret6, SecretSharing.reconstructSecret(new byte[][]{shares6[0], shares6[1], shares6[2]})));
        assertTrue(
            Arrays.equals(secret6, SecretSharing.reconstructSecret(new byte[][]{shares6[2], shares6[3], shares6[4]})));
        assertTrue(
            Arrays.equals(secret6, SecretSharing.reconstructSecret(new byte[][]{shares6[0], shares6[2], shares6[4]})));

        byte[] secret7 = new byte[0];
        SecretShareGroup group7 = SecretShareGroup.createFromSecret(secret7, 4, random);
        byte[][] shares7 = new byte[][]{
            group7.share(0).toBytes(), group7.share(1).toBytes(), group7.share(5).toBytes(),
            group7.share(12345).toBytes(), group7.share(6789).toBytes(), group7.share(Integer.MAX_VALUE).toBytes()};
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new byte[][]{shares7[0], shares7[1], shares7[2], shares7[3]})));
        assertTrue(
            Arrays.equals(
                secret7,
                SecretSharing.reconstructSecret(new byte[][]{shares7[2], shares7[3], shares7[4], shares7[5]})));

        byte[] secret8 = "Lorem ipsum dolor".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group8 = SecretShareGroup.createFromSecret(secret8, 1, random);
        byte[][] shares8 = new byte[][]{
            group8.share(0).toBytes(), group8.share(Integer.MAX_VALUE).toBytes(),
            group8.share(BigInteger.ONE.shiftLeft(136).subtract(BigInteger.ONE)).toBytes()};
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[0]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[1]})));
        assertTrue(
            Arrays.equals(secret8, SecretSharing.reconstructSecret(new byte[][]{shares8[2]})));
    }

    /** Tests SecretShareGroup.reconstructSecretShareGroup(SecretShare[]). */
    @Test
    public void testReconstructSecretShareGroup() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1a = SecretShareGroup.createFromSecret(secret1, 3, random);
        SecretShare[] shares = new SecretShare[]{
            group1a.share(0), group1a.share(7), group1a.share(Integer.MAX_VALUE),
            group1a.share(BigInteger.valueOf(3).shiftLeft(80)),
            group1a.share(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE))};
        SecretShareGroup group1b = SecretSharing.reconstructSecretShareGroup(
            new SecretShare[]{shares[0], shares[1], shares[2]});
        SecretShareGroup group1c = SecretSharing.reconstructSecretShareGroup(
            new SecretShare[]{shares[0], shares[2], shares[4]});
        assertTrue(
            Arrays.equals(
                secret1,
                SecretSharing.reconstructSecret(
                    new SecretShare[]{shares[3], group1b.share(42), group1c.share(BigInteger.ONE.shiftLeft(80))})));

        byte[] secret2 = new byte[0];
        SecretShareGroup group2a = SecretShareGroup.createFromSecret(secret2, 2, random);
        SecretShareGroup group2b = SecretSharing.reconstructSecretShareGroup(
            new SecretShare[]{group2a.share(4), group2a.share(13)});
        assertTrue(
            Arrays.equals(
                secret2, SecretSharing.reconstructSecret(new SecretShare[]{group2a.share(4), group2b.share(13)})));

        byte[] secret3 = "Lorem ipsum dolor".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group3a = SecretShareGroup.createFromSecret(secret3, 1, random);
        SecretShareGroup group3b = SecretSharing.reconstructSecretShareGroup(new SecretShare[]{group3a.share(27)});
        assertTrue(Arrays.equals(secret3, SecretSharing.reconstructSecret(new SecretShare[]{group3b.share(14)})));
    }

    /** Tests SecretShareGroup.reconstructSecretShareGroup(byte[], SecretShare[]). */
    @Test
    public void testReconstructSecretShareGroupUsingSecret() {
        byte[] secret1 = "Lorem ipsum dolor sit amet, consectetu".getBytes(StandardCharsets.US_ASCII);
        SecretShareGroup group1a = SecretShareGroup.createFromSecret(secret1, 3, random);
        SecretShare[] shares = new SecretShare[]{
            group1a.share(0), group1a.share(7), group1a.share(Integer.MAX_VALUE),
            group1a.share(BigInteger.valueOf(3).shiftLeft(80)),
            group1a.share(BigInteger.ONE.shiftLeft(152).subtract(BigInteger.ONE))};
        SecretShareGroup group1b = SecretSharing.reconstructSecretShareGroup(
            secret1, new SecretShare[]{shares[0], shares[1]});
        SecretShareGroup group1c = SecretSharing.reconstructSecretShareGroup(
            secret1, new SecretShare[]{shares[2], shares[4]});
        assertTrue(
            Arrays.equals(
                secret1,
                SecretSharing.reconstructSecret(
                    new SecretShare[]{shares[3], group1b.share(42), group1c.share(BigInteger.ONE.shiftLeft(80))})));

        byte[] secret2 = new byte[0];
        SecretShareGroup group2a = SecretShareGroup.createFromSecret(secret2, 2, random);
        SecretShareGroup group2b = SecretSharing.reconstructSecretShareGroup(
            secret2, new SecretShare[]{group2a.share(4)});
        assertTrue(
            Arrays.equals(
                secret2, SecretSharing.reconstructSecret(new SecretShare[]{group2a.share(4), group2b.share(13)})));
    }

    /** Tests SecretSharing.splitSecret where sharesNeeded is 0. */
    @Test(expected = IllegalArgumentException.class)
    public void testSplitSecretsZeroSharesNeeded() {
        SecretSharing.splitSecret(new byte[32], 0, 1, random);
    }

    /** Tests SecretSharing.splitSecret where sharesNeeded is negative. */
    @Test(expected = IllegalArgumentException.class)
    public void testSplitSecretsNegativeSharesNeeded() {
        SecretSharing.splitSecret(new byte[32], -2, 1, random);
    }

    /** Tests SecretSharing.splitSecret where sharesNeeded < sharesReturned. */
    @Test(expected = IllegalArgumentException.class)
    public void testSplitSecretsSharesReturnedLessThanSharesNeeded() {
        SecretSharing.splitSecret(new byte[32], 3, 2, random);
    }

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) on an empty array of SecretShares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretNoShares() {
        SecretSharing.reconstructSecret(new SecretShare[0]);
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) on an empty array. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretBytesNoShares() {
        SecretSharing.reconstructSecret(new byte[0][]);
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(SecretShare[]) on an empty array of SecretShares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupNoShares() {
        SecretSharing.reconstructSecretShareGroup(new SecretShare[0]);
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) on an empty array of SecretShares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupUsingSecretNoShares() {
        SecretSharing.reconstructSecretShareGroup(new byte[32], new SecretShare[0]);
    }

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) with too few secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretTooFewShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(new SecretShare[]{group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) with too few secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretBytesTooFewShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(new byte[][]{group.share(0).toBytes()});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(SecretShare[]) with too few secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupTooFewShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecretShareGroup(new SecretShare[]{group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) with too few secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupUsingSecretTooFewShares() {
        byte[] secret = new byte[32];
        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretSharing.reconstructSecretShareGroup(secret, new SecretShare[]{group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) with too many secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretTooManyShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(new SecretShare[]{group.share(0), group.share(1), group.share(2)});
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) with too many secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretBytesTooManyShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(
            new byte[][]{group.share(0).toBytes(), group.share(1).toBytes(), group.share(2).toBytes()});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(SecretShare[]) with too many secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupTooManyShares() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecretShareGroup(new SecretShare[]{group.share(0), group.share(1), group.share(2)});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) with too many secret shares. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupUsingSecretTooManyShares() {
        byte[] secret = new byte[32];
        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, 2, random);
        SecretSharing.reconstructSecretShareGroup(secret, new SecretShare[]{group.share(0), group.share(1)});
    }

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) with a duplicated secret share. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretDuplicateShare() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(new SecretShare[]{group.share(0), group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) with a duplicated secret share. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretBytesDuplicateShare() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecret(new byte[][]{group.share(0).toBytes(), group.share(0).toBytes()});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(SecretShare[]) with a duplicated secret share. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupDuplicateShare() {
        SecretShareGroup group = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretSharing.reconstructSecretShareGroup(new SecretShare[]{group.share(0), group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) with a duplicated secret share. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupUsingSecretDuplicateShare() {
        byte[] secret = new byte[32];
        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretSharing.reconstructSecretShareGroup(secret, new SecretShare[]{group.share(0), group.share(0)});
    }

    /** Tests SecretSharing.reconstructSecret(SecretShare[]) with secret shares from different groups. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretDifferentGroups() {
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(new byte[33], 2, random);
        SecretSharing.reconstructSecret(new SecretShare[]{group1.share(0), group2.share(1)});
    }

    /** Tests SecretSharing.reconstructSecret(byte[][]) with secret shares from different groups. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretBytesDifferentGroups() {
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(new byte[33], 2, random);
        SecretSharing.reconstructSecret(new byte[][]{group1.share(0).toBytes(), group2.share(1).toBytes()});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(SecretShare[]) with secret shares from different groups. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupDifferentGroups() {
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(new byte[33], 2, random);
        SecretSharing.reconstructSecretShareGroup(new SecretShare[]{group1.share(0), group2.share(1)});
    }

    /**
     * Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) with secret shares from different groups.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupUsingSecretDifferentGroups() {
        byte[] secret1 = new byte[32];
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(secret1, 3, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(new byte[33], 3, random);
        SecretSharing.reconstructSecretShareGroup(secret1, new SecretShare[]{group1.share(0), group2.share(1)});
    }

    /** Tests SecretSharing.reconstructSecretShareGroup(byte[], SecretShare[]) with a secret of the wrong length. */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretShareGroupWrongSecretLength() {
        byte[] secret = new byte[32];
        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, 3, random);
        SecretSharing.reconstructSecretShareGroup(new byte[33], new SecretShare[]{group.share(0), group.share(1)});
    }

    /**
     * Tests SecretSharing.reconstructSecret(SecretShare[]) with a secret share from a group obtained using
     * SecretSharing.reconstructSecretShareGroup.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructSecretDifferentReconstructedGroup() {
        SecretShareGroup group1 = SecretShareGroup.createFromSecret(new byte[32], 2, random);
        SecretShareGroup group2 = SecretShareGroup.createFromSecret(new byte[33], 2, random);
        SecretShareGroup group3 = SecretSharing.reconstructSecretShareGroup(
            new SecretShare[]{group2.share(0), group2.share(1)});
        SecretSharing.reconstructSecret(new SecretShare[]{group1.share(0), group3.share(1)});
    }
}
