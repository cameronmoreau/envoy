# Token Encryption Scheme

The TokenEncryptor class implements an encryption scheme for encrypting tokens
to be securely stored as cookies.

The scheme first uses the HKDF key derivation algorithm along with a configured
secret and hash algorithm to derive a key of a suitable size for the configured
encryption algorithm. The encryption algorithm (currently supporting only
AES128GCM or AES256GCM) is then used with this key and a random nonce to
encrypt the token.

Finally the nonces and ciphertext are concatenated together and the result is
base64 encoded for transmission to a client.

The reasons for choosing this scheme, where a key is derived each time rather
than using the configured secret directly, are to prevent nonce reuse and
to mitigate key exhaustion, both of which can be issues with the GCM encryption
algorithms if reusing the same key.
