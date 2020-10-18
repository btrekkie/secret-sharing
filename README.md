# NEVER USE THIS
NEVER USE THIS. I am not a cryptography specialist. You should only use
cryptographic functions that were implemented by a specialist in cryptography
and have been carefully vetted and tested. Otherwise, they are liable to have
vulnerabilities. This library is subject to timing attacks. This software is
purely for instructional purposes.

# Description
`secret-sharing` provides the ability to split a secret into shares, which may
later be combined to reconstruct the secret. When splitting a secret, a
`sharesNeeded` number is passed in as an argument. The secret can later be
reconstructed by calling `SecretSharing.reconstructSecret` with an array of
`sharesNeeded` distincts shares. For example, `secret-sharing` could be used to
split a secret into five shares, any three of which could be used to reconstruct
the secret.

`secret-sharing` uses Shamir's Secret Sharing algorithm. This is an
information-theoretically secure algorithm. This means that possession of
`sharesNeeded - 1` secret shares gives no information at all about the secret,
apart from the number of bytes it contains. (That is, given a specific value for
the secret, a set of `sharesNeeded - 1` secret shares will have the same random
distribution as they would for any other specific secret of the same length.
This assumes that the random number generator is perfectly random. In practice,
it is not perfectly random, so the above claims must be relaxed accordingly.)

# Features
* Split a secret into multiple shares, which may later be combined to recover
  the secret.
* Uses an information-theoretically secure algorithm.
* Additional shares can be generated as needed. It is not necessary to generate
  all of the shares up front.

# Limitations
* Not written by a cryptography specialist or carefully vetted or tested. For
  these reasons, this library is liable to have vulnerabilities and should never
  be used.
* Timing attacks are possible. In other words, information-theoretic security is
  not guaranteed if an attacker has knowledge of how long the method calls took
  to run.

# Example
```java
// Generate secret shares, with 3 of 5 needed to reconstruct the secret
byte[] secret = "a 128-bit secret".getBytes(StandardCharsets.US_ASCII);
byte[][] shares = SecretSharing.splitSecret(secret, 3, 5);

// Print the shares
for (byte[] share : shares) {
    System.out.println(Base64.getEncoder().encodeToString(share));
}

// Reconstruct the secret
byte[] reconstructedSecret = SecretSharing.reconstructSecret(
    new byte[][]{shares[0], shares[1], shares[4]});
Arrays.equals(secret, reconstructedSecret); // Returns true
```

# Documentation
See <https://btrekkie.github.io/secret-sharing/index.html> for API
documentation.
