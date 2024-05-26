## RSAKEY Class: Secure Signing and Verification with RSA-PSS

This document explains the `RSAKEY` class, which provides functionalities for signing and verifying data using the RSA public-key cryptography algorithm with Probabilistic Signature Scheme (PSS) padding. It supports SHA-256, SHA-384, and SHA-512 hashing algorithms and allows customization of the salt length.

### Functionality

* **Signing:** Creates a digital signature for a given message using a provided private key.
* **Verification:** Validates a signature for a message using a corresponding public key.

### Supported Features

* RSA-PSS padding for enhanced security.
* SHA-256, SHA-384, and SHA-512 hashing algorithms.
* Customizable salt length for PSS padding (optional).

### Usage

**1. Constructor:**

```javascript
import { RSAKEY } from 'https://deno.land/x/rsakey/mod.js'
// or from 'https://deno.land/x/rsakey/src/index.js to use unpacked version
const rsaKey = new RSAKEY(privateKeyPemString, options);
```

* `privateKeyPemString`: A string containing the private key in PEM format.
* `options` (optional): An object with the following properties (defaults provided):
    * `sha`: {number} The desired hashing algorithm (`256`, `384`, or `512`; defaults to `256`).
    * `saltLength`: {number} The salt length for PSS padding (defaults to `hash.length/8`).

**2. Signing:**

```javascript
const signature = rsaKey.sign(message);
```

* `message`: {Uint8Array} The data to be signed.
* Returns: {Uint8Array} The generated signature.

**3. Verification:**

```javascript
const isValid = rsaKey.verify(publicKeyObject, message, signature);
```

* `message`: {Uint8Array} The data that was signed.
* `signature`: {Uint8Array} The signature to be verified (byte array).
* `publicKeyObject`: {n:bigInt, e:bigInt} An object containing modulus - n and public exponent - e.
* Returns: `consistent` if the signature is valid, `inconsistent` otherwise.

### Example

```javascript
const privateKeyPem = '-----BEGIN RSA PRIVATE KEY-----...\n-----END RSA PRIVATE KEY-----';
const message = new TextEncoder().encode('This is the message to be signed');

const rsaKey = new RSAKEY(privateKeyPem); // Use default options (SHA-256)

const signature = rsaKey.sign(message);

// ... (send the message and signature to another party)

const publicKeyPem = '-----BEGIN RSA PUBLIC KEY-----...\n-----END RSA PUBLIC KEY-----';
const isValid = rsaKey.verify(message, signature, publicKeyPem);

if (isValid=='consistent') {
  console.log('Signature is valid!');
} else {
  console.error('Signature verification failed!');
}
```

This `RSAKEY` class provides a convenient way to implement secure signing and verification using RSA-PSS with various SHA hashing options. By following these guidelines, you can effectively leverage this class for your cryptographic needs.

### Notes

* Please let me know for any improvement or feedback.

### Sponsorship

I need Sponsorship to maintain and create other codes.
Just click one of the following links
- https://github.com/sponsors/Srabutdotcom
- https://paypal.me/aiconeid

