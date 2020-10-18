package com.github.btrekkie.secret_sharing;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * NEVER USE THIS. I am not a cryptography specialist. You should only use cryptographic functions that were implemented
 * by a specialist in cryptography and have been carefully vetted and tested. Otherwise, they are liable to have
 * vulnerabilities. This library is subject to timing attacks. This software is purely for instructional purposes.
 *
 * -----
 *
 * Provides the ability to split a secret into shares, which may later be combined to reconstruct the secret. When
 * splitting a secret, a sharesNeeded number is passed in as an argument. The secret can later be reconstructed by
 * calling reconstructSecret with an array of sharesNeeded distincts shares. For example, SecretSharing could be used to
 * split a secret into five shares, any three of which could be used to reconstruct the secret.
 *
 * SecretSharing uses Shamir's Secret Sharing algorithm. This is an information-theoretically secure algorithm. This
 * means that possession of sharesNeeded - 1 secret shares gives no information at all about the secret, apart from the
 * number of bytes it contains. (That is, given a specific value for the secret, a set of sharesNeeded - 1 secret shares
 * will have the same random distribution as they would for any other specific secret of the same length. This assumes
 * that the random number generator is perfectly random. In practice, it is not perfectly random, so the above claims
 * must be relaxed accordingly.)
 *
 * Each secret share stores the number of bytes in the secret. If the secret comes from a variable-length domain, you
 * may want to pad the secret by appending 0 bytes to the end. By padding the secret to a fixed length, you can conceal
 * the length of the underlying secret information.
 */
public class SecretSharing {
    /**
     * Splits the specified secret into sharesReturned shares. This returns an array of the shares, each of which is
     * represented as a byte array.
     *
     * This is a convenience method. It is equivalent to creating a SecretShareGroup using
     * SecretShareGroup.createFromSecret(secret, sharesNeeded, random), obtaining the shares numbered 0 to
     * sharesReturned - 1, and serializing them using toBytes().
     *
     * @param secret The secret to split.
     * @param sharesNeeded The number of shares needed to reconstruct the secret.
     * @param sharesReturned The number of shares to return.
     * @param random The SecureRandom instance to use as the source of randomness.
     * @return The secret shares.
     * @throws IllegalArgumentException If sharesNeeded <= 0 or sharesReturned < sharesNeeded.
     */
    public static byte[][] splitSecret(byte[] secret, int sharesNeeded, int sharesReturned, SecureRandom random) {
        if (sharesNeeded <= 0) {
            throw new IllegalArgumentException("sharesNeeded must be positive");
        }
        if (sharesReturned < sharesNeeded) {
            throw new IllegalArgumentException("sharesReturned must be at least sharesNeeded");
        }

        SecretShareGroup group = SecretShareGroup.createFromSecret(secret, sharesNeeded, random);
        byte[][] shares = new byte[sharesReturned][];
        for (int i = 0; i < sharesReturned; i++) {
            shares[i] = group.share(i).toBytes();
        }
        return shares;
    }

    /**
     * Splits the specified secret into sharesReturned shares. This returns an array of the shares, each of which is
     * represented as a byte array.
     *
     * This is a convenience method. It is equivalent to creating a SecretShareGroup using
     * SecretShareGroup.createFromSecret(secret, sharesNeeded), obtaining the shares numbered 0 to sharesReturned - 1,
     * and serializing them using toBytes().
     *
     * @param secret The secret to split.
     * @param sharesNeeded The number of shares needed to reconstruct the secret.
     * @param sharesReturned The number of shares to return.
     * @return The secret shares.
     * @throws IllegalArgumentException If sharesNeeded <= 0 or sharesReturned < sharesNeeded.
     */
    public static byte[][] splitSecret(byte[] secret, int sharesNeeded, int sharesReturned) {
        return splitSecret(secret, sharesNeeded, sharesReturned, new SecureRandom());
    }

    /**
     * Reconstructs and returns the secret from the specified shares.
     * @throws IllegalArgumentException If "shares" does not contain exactly sharesNeeded elements, it contains a
     *     duplicate share, we are able to detect that it contains shares from different SecretShareGroups.
     */
    public static byte[] reconstructSecret(SecretShare[] shares) {
        // Use the Lagrange polynomial to interpolate the polynomial at x = 0. This gives us
        // SecretSharingUtil.encodeSecret(secret). See https://en.wikipedia.org/wiki/Lagrange_polynomial .
        SecretSharingUtil.checkShares(shares);
        SecretShareGroupParams params = shares[0].params;
        BigInteger result = BigInteger.ZERO;
        BigInteger modulus = params.modulus;
        for (int i = 0; i < shares.length; i++) {
            BigInteger numerator = shares[i].y;
            BigInteger denominator = BigInteger.ONE;
            for (int j = 0; j < shares.length; j++) {
                if (j != i) {
                    numerator = numerator.multiply(shares[j].x).mod(modulus);
                    denominator = denominator.multiply(shares[j].x.subtract(shares[i].x).mod(modulus)).mod(modulus);
                }
            }
            result = result.add(numerator.multiply(denominator.modInverse(modulus)).mod(modulus)).mod(modulus);
        }

        if (result.bitLength() > 8 * params.secretLength) {
            throw new IllegalArgumentException("Invalid secret shares");
        }
        return SecretSharingUtil.decodeSecret(result, params.secretLength);
    }

    /**
     * Reconstructs and returns the secret from the specified serialized shares.
     * @param shareBytes The secret shares, as in the return value of splitSecret.
     * @return The secret.
     * @throws IllegalArgumentException If shareBytes does not contain exactly sharesNeeded elements, it contains a
     *     duplicate share, we are able to detect that it contains shares from different SecretShareGroups, or we detect
     *     that one of the specified byte arrays is not a valid encoding of a SecretShare.
     */
    public static byte[] reconstructSecret(byte[][] shareBytes) {
        SecretShare[] shares = new SecretShare[shareBytes.length];
        for (int i = 0; i < shareBytes.length; i++) {
            shares[i] = SecretShare.createFromBytes(shareBytes[i]);
        }
        return reconstructSecret(shares);
    }

    /**
     * Reconstructs and returns the SecretShareGroup that the specified shares belong to. Once reconstructed, it is
     * possible to generate additional secret shares for this group.
     *
     * For performance reasons, if additional secret shares may be required later, it may be better to store the
     * SecretShareGroup in advance (e.g. using toBytes() and createFromBytes) rather than calling
     * reconstructSecretShareGroup. However, note that the secret itself would be stored as part of the
     * SecretShareGroup.
     *
     * @throws IllegalArgumentException If "shares" does not contain exactly sharesNeeded elements, it contains a
     *     duplicate share, or we are able to detect that it contains shares from different SecretShareGroups.
     */
    public static SecretShareGroup reconstructSecretShareGroup(SecretShare[] shares) {
        return reconstructGroup(null, shares);
    }

    /**
     * Reconstructs and returns the SecretShareGroup that the specified secret and secret shares belong to. Once
     * reconstructed, it is possible to generate additional secret shares for this group.
     *
     * For performance reasons, if additional secret shares may be required later, it may be better to store the
     * SecretShareGroup in advance (e.g. using toBytes() and createFromBytes) rather than calling
     * reconstructSecretShareGroup. However, note that the secret itself would be stored as part of the
     * SecretShareGroup.
     *
     * @throws IllegalArgumentException If "shares" is empty or does not contain exactly sharesNeeded - 1 elements, it
     *     contains a duplicate share, we are able to detect that it contains shares from different SecretShareGroups,
     *     or the secret has a different length than that of the group that the shares belong to.
     */
    public static SecretShareGroup reconstructSecretShareGroup(byte[] secret, SecretShare[] shares) {
        if (secret == null) {
            throw new IllegalArgumentException("The secret may not be null");
        }
        return reconstructGroup(secret, shares);
    }

    /**
     * Executes the elimination phase of Gaussian elimination. This consists of modifying a matrix "matrix" that does
     * not have any 0s in the diagonal until it is upper triangular and has only 1s in the diagonal. See the comments
     * for the implementation of computeRref.
     * @param matrix The matrix. This is a rowCount x (rowCount + 1) matrix stored in row-major order. All of its
     *     elements are in the range [0, modulus).
     * @param rowCount The number of rows in the matrix.
     * @param modulus The modulus. This must be a prime number. This operation is performed with respect to
     *     addition and multiplication mod "modulus".
     */
    private static void rrefEliminate(BigInteger[] matrix, int rowCount, BigInteger modulus) {
        int columnCount = rowCount + 1;
        for (int row1 = 0; row1 < rowCount; row1++) {
            BigInteger inverse = matrix[columnCount * row1 + row1].modInverse(modulus);
            matrix[columnCount * row1 + row1] = BigInteger.ONE;
            for (int column = row1 + 1; column < columnCount; column++) {
                int index = columnCount * row1 + column;
                matrix[index] = matrix[index].multiply(inverse).mod(modulus);
            }

            for (int row2 = row1 + 1; row2 < rowCount; row2++) {
                BigInteger mult = matrix[columnCount * row2 + row1];
                matrix[columnCount * row2 + row1] = BigInteger.ZERO;
                for (int column = row1 + 1; column < columnCount; column++) {
                    int index1 = columnCount * row1 + column;
                    int index2 = columnCount * row2 + column;
                    matrix[index2] = matrix[index2].subtract(matrix[index1].multiply(mult).mod(modulus)).mod(modulus);
                }
            }
        }
    }

    /**
     * Executes the substitution phase of Gaussian elimination. This consists of modifying an upper triangular matrix
     * "matrix" that has only 1s in the diagonal until the only non-zero entries are in the diagonal and the last
     * column. See the comments for the implementation of computeRref.
     * @param matrix The matrix. This is a rowCount x (rowCount + 1) matrix stored in row-major order. All of its
     *     elements are in the range [0, modulus).
     * @param rowCount The number of rows in the matrix.
     * @param modulus The modulus. This must be a prime number. This operation is performed with respect to
     *     addition and multiplication mod "modulus".
     */
    private static void rrefSubstitute(BigInteger[] matrix, int rowCount, BigInteger modulus) {
        int columnCount = rowCount + 1;
        for (int row1 = rowCount - 1; row1 > 0; row1--) {
            for (int row2 = 0; row2 < row1; row2++) {
                BigInteger mult = matrix[columnCount * row2 + row1];
                matrix[columnCount * row2 + row1] = BigInteger.ZERO;
                int index1 = columnCount * row1 + rowCount;
                int index2 = columnCount * row2 + rowCount;
                matrix[index2] = matrix[index2].subtract(matrix[index1].multiply(mult).mod(modulus)).mod(modulus);
            }
        }
    }

    /**
     * Changes "matrix" to its reduced row echelon form, with respect to addition and multiplication mod "modulus". This
     * method assumes that "matrix" that does not have any 0s in the diagonal. See
     * https://en.wikipedia.org/wiki/Row_echelon_form#Reduced_row_echelon_form .
     * @param matrix The matrix. This is a rowCount x (rowCount + 1) matrix stored in row-major order. All of its
     *     elements are in the range [0, modulus).
     * @param rowCount The number of rows in the matrix.
     * @param modulus The modulus. This must be a prime number.
     */
    private static void computeRref(BigInteger[] matrix, int rowCount, BigInteger modulus) {
        /* This is implemented using Gaussian elimination. See https://en.wikipedia.org/wiki/Gaussian_elimination . This
         * consists of an elimination phase, in which we make the matrix upper triangular and all of the diagonal
         * entries 1, and a substitution phase, in which we make all entries in the upper triangle 0, apart from the
         * last column.
         *
         * For the elimination phase, we iterate over the rows from top to bottom. For each row, we multiply it by the
         * inverse of the diagonal cell, so that the diagonal cell contains a 1. Then we iterate over the rows below it,
         * subtracting a multiple of the row so that the cell below the diagonal cell is 0.
         *
         * For the substitution phase, we iterate over the rows from bottom to top. For each row, we iterate over the
         * rows above it, subtracting a multiple of the row so that the cell above the diagonal cell is 0.
         */
        rrefEliminate(matrix, rowCount, modulus);
        rrefSubstitute(matrix, rowCount, modulus);
    }

    /**
     * Common implementation of reconstructSecretShareGroup(SecretShare[]) and
     * reconstructSecretShareGroup(byte[], SecretShare[]).
     * @param secret The secret. This is null if called from reconstructSecretShareGroup(SecretShare[]).
     * @param shares The secret shares.
     * @return The SecretShareGroup.
     */
    private static SecretShareGroup reconstructGroup(byte[] secret, SecretShare[] shares) {
        /* Each SecretShare S gives us a linear equation of the form C[0] + C[1] * S.x + C[2] * S.x * S.x + ... = S.y
         * (mod params.modulus), where C is SecretShareGroup.coefficients. This method works by solving the relevant
         * system of linear equations for C, using Gaussian elimination. See the comments for the implementation of
         * computeRref. (The secret gives us a linear equation of the form
         * C[0] = SecretSharingUtil.encodeSecret(secret).)
         */

        // Validate the arguments
        SecretSharingUtil.checkShares(shares, secret != null);
        SecretShareGroupParams params = shares[0].params;
        if (secret != null && secret.length != params.secretLength) {
            throw new IllegalArgumentException(
                "The specified secret does not belong to the same SecretShareGroup as the specified SecretShares");
        }

        // Construct the matrix
        int rowCount = params.sharesNeeded;
        int columnCount = rowCount + 1;
        BigInteger[] matrix = new BigInteger[rowCount * columnCount];

        // Add the linear equation for "secret"
        int offset;
        if (secret == null) {
            offset = 0;
        } else {
            offset = 1;
            matrix[0] = BigInteger.ONE;
            for (int i = 1; i < rowCount; i++) {
                matrix[i] = BigInteger.ZERO;
            }
            matrix[rowCount] = SecretSharingUtil.encodeSecret(secret);
        }

        // Add the linear equations for "shares"
        for (int i = 0; i < shares.length; i++) {
            SecretShare share = shares[i];
            BigInteger value = BigInteger.ONE;
            for (int j = 0; j < rowCount; j++) {
                matrix[columnCount * (i + offset) + j] = value;
                value = value.multiply(share.x).mod(params.modulus);
            }
            matrix[columnCount * (i + offset) + rowCount] = share.y;
        }

        // Solve for the coefficients
        computeRref(matrix, rowCount, params.modulus);
        BigInteger[] coefficients = new BigInteger[rowCount];
        for (int i = 0; i < rowCount; i++) {
            coefficients[i] = matrix[columnCount * i + rowCount];
        }
        if (coefficients[0].bitLength() > 8 * params.secretLength) {
            throw new IllegalArgumentException("Invalid secret shares");
        }
        return new SecretShareGroup(params, coefficients);
    }
}
