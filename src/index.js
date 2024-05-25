import { ASN1 } from "npm:@lapo/asn1js"
import { Base64 } from "npm:@lapo/asn1js/base64.js"
import { Defs } from "npm:@lapo/asn1js/defs.js"
import bigInt from 'npm:big-integer'
import { validate } from 'https://deno.land/x/validatevalue@v1.0.2/mod.js'
import * as sha256 from "@stablelib/sha256"
import * as sha384 from "@stablelib/sha384"
import * as sha512 from "@stablelib/sha512"

export class RSAKey {
   // default value for SHA algoritm and saltLength
   validSHA = [256, 384, 512] // only available for this hash algoritm
   sha = 256; // by default
   saltLength = 32; // by default, the same as sha bytes 256 / 8
   hash = { sha256, sha384, sha512 }; // use hash['sha'+this.sha].hash(Uint8Array)
   OS2IP= OS2IP;
   I2OSP=I2OSP;
   I2OSP_array=I2OSP_array;
   I2OSP_uint8=I2OSP_array;
   RSASP1=RSASP1;
   RSAVP1=RSAVP1;
   /**
    * 
    * @param {PEMString} pem 
    * @param {{sha:256,saltLength:32,salt:Uint8Array}} options 
    */
   constructor(pem, options) {
      if (isUndefined(pem)) return TypeError(`Parameter 1 is mandatory in the form of PEM String`);
      if (isPrivateKeyPemString(pem) == false) return TypeError(`Parameter 1 is not in the form of PEM String`);
      // the uint8array from pem string
      this.enc = Base64.unarmor(pem);
      // the asn1 object from uint8array
      this.asn1 = ASN1.decode(this.enc);
      // get type and key
      const { type, key } = extractKey(this.asn1);
      if (type.name !== 'RSAPrivateKey') return TypeError(`Expected RSAPrivateKey but got ${type.name}`);

      this.type = type;
      this.key = key;

      // modulus n in uint8array
      this.nUint8 = this.component('n')

      // version as 
      this.version = key.sub[0].content();

      /** @type {bigInt} modulus - n */
      this.n = bigInt(key.sub[1].content().split(/\n/)[1]);

      /** @type {bigInt} public exponent - e */
      this.e = bigInt(key.sub[2].content());

      /** @type {bigInt} private exponent - d */
      this.d = bigInt(key.sub[3].content().split(/\n/)[1]);
      // prime1 - first factor - p
      this.p = bigInt(key.sub[4].content().split(/\n/)[1]);
      // prime2 - second factor - q
      this.q = bigInt(key.sub[5].content().split(/\n/)[1]);
      // exponent1 - first factor's CRT exponent - dP
      this.dP = bigInt(key.sub[6].content().split(/\n/)[1]);
      // exponent2 - second factor's CRT exponent - dQ
      this.dQ = bigInt(key.sub[7].content().split(/\n/)[1]);
      // coefficient - CRT coefficient - qInv
      this.qInv = bigInt(key.sub[8].content().split(/\n/)[1]);//console.log('line 47')

      // set options for sha and saltLength if provided
      if (isDefined(options) && validate(options, [{ sha: 256, saltLength: 32 }])) {
         if (options.sha && this.validSHA.includes(options.sha)) this.sha = options.sha;
         if (isDefined(options.saltLength) && (options.saltLength !== this.saltLength)) {
            this.saltLength = options.saltLength//Math.min(this.sha / 8, Math.max(0, options.saltLength))
         }
         if (isDefined(options.salt)) {
            this.salt = options.salt;
            this.saltLength = this.salt.length
         }
      }
   }
   /**
    * To get privateKey component in Uin8Array
    * @param {string|number} component 
    * @returns {Uint8Array}
    */
   component(component) {
      let isValid = validate(component, ['number', 'string'], ['n', 'd', 'p', 'q', 'dp', 'dq', 'qinv', 1, 3, 4, 5, 6, 7, 8])
      if (isValid !== true) return isValid
      const componentMap = [
         'n-1', 'd-3', 'p-4', 'q-5', 'dp-6', 'dq-7', 'qinv-8'
      ]
      let index;
      if (typeof (component) == 'number') {
         index = component
      } else if (typeof (component) == 'string') {
         index = componentMap.find(e => e.includes(component.toLowerCase()))?.split('-')[1]
      } else { return 'Error: expected number or string of component' }

      const { enc, pos } = this.key.sub[index].stream;
      const { header, length } = this.key.sub[index];

      // check zerro padding
      const start = pos + header
      const end = start + length;
      const padding = (enc[start] == 0) ? 1 : 0; //console.log('line 74')

      return enc.slice(start + padding, end)
   }

   /**
    * DONE - welldone
    * LINK - https://datatracker.ietf.org/doc/html/rfc8017#page-63
    * @param {Uint8Array} mgfSeed 
    * @param {number} maskLen 
    * @returns 
    */
   MGF1(mgfSeed, maskLen) {
      let isValid = validate(mgfSeed, [Uint8Array])
      if (isValid !== true) return Error('parameter 1 should be Uint8Array')
      isValid = validate(maskLen, ['number']);
      if (isValid !== true) return Error('parameter 2 should be "number"')
      // 1. Check if mask is too long
      const hLen = this.sha / 8
      if (maskLen > Math.pow(2, 32) * hLen) { // NOTE - can be limited to lower value 65536 0x10_000
         throw new Error("mask too long");
      }

      // 2. Initialize empty string T
      let T = new Uint8Array(0);

      // 3. Loop for counter
      const counterLength = 4; // Assuming 32-bit counter
      const loopCount = Math.ceil(maskLen / hLen) - 1;// maskLen//
      for (let counter = 0; counter <= loopCount; counter++) {
         // A. Convert counter to octet string C
         const C = I2OSP_uint8(counter, counterLength);

         // B. Concatenate hash and C to T
         const mgfSeedAndC = merge(mgfSeed, C)//new Uint8Array(mgfSeed.length + C.length);
         const hash = this.hash['sha' + this.sha].hash(mgfSeedAndC);
         T = merge(T, hash)
      }

      // 4. Return leading maskLen octets
      return T.slice(0, maskLen);
   }
   /**
    * LINK - https://datatracker.ietf.org/doc/html/rfc8017#page-40
    * @param {Uint8Array} M message in Uint8Array 
    * @returns {Uint8Array}
    */
   EMSA_PSS_ENCODE(M) {
      // 0. validate input M as Uint8Array
      validate(M, [Uint8Array])

      // 1. Check if message is too long
      if (M.length > Math.pow(2, 61) - 1) {
         throw new Error("message too long");
      }

      // 2. Hash the message
      // DONE - 
      const mHash = this.hash['sha' + this.sha].hash(M); //console.log('line 125')
      const hLen = mHash.length;

      // LINK - https://datatracker.ietf.org/doc/html/rfc8017#page-33
      // NOTE - EM length is at most modBits -1; modBits is the length of of the RSA modulus n
      const emBits = this.nUint8.length * 8 - 1//128 * 8 - 1;//8 * hLen + 8 * sLen + 9 + 2 
      // Calculate emLen based on emBits (corrected formula)
      const emLen = Math.ceil(emBits / 8);

      // 3. Check if emLen is sufficient
      const sLen = this.saltLength
      if (emLen < hLen + sLen + 2) {
         throw new Error(`Error: emLen less than ${hLen} + ${sLen} + 2`);
      }

      // 4. Generate salt
      const salt = this.salt ? this.salt : self.crypto.getRandomValues(new Uint8Array(sLen));

      // 5. Concatenate M'
      const M_prime = merge(new Uint8Array(8), mHash, salt)

      // 6. Hash M'
      const H = this.hash['sha' + this.sha].hash(M_prime);

      // 7. Generate PS
      const PS = new Uint8Array(emLen - sLen - hLen - 2);

      // 8. Construct DB
      const DB = merge(PS, new Uint8Array([0x01]), salt)

      // 9. Generate dbMask
      const dbMask = this.MGF1(H, DB.length);

      // 10. Apply mask
      const maskedDB = new Uint8Array(DB.length);
      for (let i = 0; i < DB.length; i++) {
         maskedDB[i] = DB[i] ^ dbMask[i];
      }

      // 11. Set leftmost bits to zero
      const newMaskedDB = setFirstBitsInFirstOctetsBy0(maskedDB, emLen, emBits);
      // 12. Construct EM
      return merge(newMaskedDB, H, new Uint8Array([0xbc]))
      return EM;
   }

   /**
    * 
    * @param {Uint8Array} M 
    * @param {Uint8Array} EM 
    * @returns {'consistent'|'inconsistent'}
    */
   EMSA_PSS_VERIFY(M, EM) {
      // 0. validate M and EM as Uint8Array
      validate(M, [Uint8Array]);
      validate(EM, [Uint8Array]);

      // 1. Check if message is too long
      if (M.length > Math.pow(2, 61) - 1) {
         return "inconsistent";
      }

      // 2. Hash the message
      const mHash = this.hash['sha' + this.sha].hash(M);
      const hLen = mHash.length;

      // LINK - https://datatracker.ietf.org/doc/html/rfc8017#page-33
      // NOTE - EM length is at most modBits -1; modBits is the length of of the RSA modulus n
      const emBits = this.nUint8.length * 8 - 1//128 * 8 - 1;//8 * hLen + 8 * sLen + 9 + 2 
      // Calculate emLen based on emBits (corrected formula)
      const emLen = Math.ceil(emBits / 8);

      // 3. Check if emLen is sufficient
      const sLen = this.saltLength
      if (emLen < hLen + sLen + 2) {
         return "inconsistent";
      }

      // 4. Check rightmost octet
      if (EM[EM.length - 1] !== 0xbc) {
         return "inconsistent";
      }

      // 5. Separate maskedDB and H
      const maskedDB = EM.slice(0, emLen - hLen - 1);
      const H = EM.slice(emLen - hLen - 1, emLen - 1);

      // 6. Check leftmost bits of maskedDB
      const isLeftMost0 = checkFirstBitsInFirstOctetsIs0(maskedDB,emLen, emBits)
      if(isLeftMost0==false) return "inconsistent";

      // 7. Generate dbMask
      const dbMask = this.MGF1(H, maskedDB.length);

      // 8. Apply mask
      const DB = new Uint8Array(maskedDB.length);
      for (let i = 0; i < DB.length; i++) {
         DB[i] = maskedDB[i] ^ dbMask[i];
      }

      // 9. Set leftmost bits to zero
      const newDB = setFirstBitsInFirstOctetsBy0(DB, emLen, emBits);

      // 10. Check DB format
      // LINK - https://github.com/golang/go/blob/master/src/crypto/rsa/pss.go row 173
      const psLen = emLen - hLen - sLen - 2
      if (!newDB.slice(0, psLen).every(byte => byte === 0) || newDB[psLen] !== 0x01) {
         return "inconsistent";
      }

      // 11. Extract salt
      const salt = DB.slice(DB.length - sLen);

      // 12. Construct M'
      const M_prime = merge(new Uint8Array(8), mHash, salt)

      // 13. Hash M'
      const H_prime = this.hash['sha' + this.sha].hash(M_prime);

      // 14. Compare hash values
      return H_prime.every((byte, index) => byte === H[index]) ? "consistent" : "inconsistent";
   }

   /**
    * To get signature of data
    * @param {Uint8Array} M 
    * @returns {Uint8Array}
    */
   RSASSA_PSS_SIGN(M) {
      // 0. validate input M as Uint8Array
      validate(M, [Uint8Array])

      // 1. EMSA-PSS encoding https://datatracker.ietf.org/doc/html/rfc8017#page-33
      const EM = this.EMSA_PSS_ENCODE(M);

      // 2.a. Convert the encoded message EM to an integer message representative m
      const m = OS2IP(EM);

      // 2.b. Apply the RSASP1 signature primitive
      const s = RSASP1(m, { n: this.n, d: this.d })

      // 2.c Convert the signature representative s to a signature S of length k octets
      const S = I2OSP_uint8(s, this.nUint8.length)

      return S

   }

   /**
    * 
    * @param {n: BigInt(0), e: BigInt(0)} RSAPublicKey 
    * @param {Uint8Array} M 
    * @param {Uint8Array} S 
    * @returns 
    */
   RSASSA_PSS_VERIFY(RSAPublicKey = { n: BigInt(0), e: BigInt(0) }, M, S) {
      // 0.a validate input RSAPublicKeyM - message as object { bigInt(n), bigInt(e) }
      validate(RSAPublicKey, [{ n: BigInt(0), e: BigInt(0) }])
      // 0.b validate input M - message as Uint8Array
      validate(M, [Uint8Array])
      // 0.c validate input S - signature as Uint8Array
      validate(S, [Uint8Array])
      /* 
      1 Length checking: If the length of the signature S is not k
      octets, output "invalid signature" and stop. */
      if (S.length !== this.nUint8.length) return TypeError(`Error: signature length at ${S.length} is not match with modulus length at ${this.nUint8.length}`)

      /* 
      2. RSA verification: 
      2.a   Convert the signature S to an integer signature
            representative s (see Section 4.2):
      */
      const s = OS2IP(S);

      /* 
      2.b.   Apply the RSAVP1 verification primitive (Section 5.2.2) to
             the RSA public key (n, e) and the signature representative
             s to produce an integer message representative m: */

      const m = RSAVP1(s, RSAPublicKey);
      /*    If RSAVP1 output "signature representative out of range",
            output "invalid signature" and stop. */

      /* 
      2.c.  Convert the message representative m to an encoded message
            EM of length emLen = \ceil ((modBits - 1)/8) octets, where
            modBits is the length in bits of the RSA modulus n (see
            Section 4.1): */
      const emLen = Math.ceil((this.nUint8.length * 8 - 1) / 8);
      const EM = I2OSP_uint8(m, emLen)
      /*       Note that emLen will be one less than k if modBits - 1 is
               divisible by 8 and equal to k otherwise.  If I2OSP outputs
               "integer too large", output "invalid signature" and stop. */

      /* 
      3.    EMSA-PSS verification: Apply the EMSA-PSS verification
            operation (Section 9.1.2) to the message M and the encoded
            message EM to determine whether they are consistent: */

      const result = this.EMSA_PSS_VERIFY(M, EM);
      if (result == 'consistent') return 'valid signature'
      return 'invalid signature'
   }

}

const isUndefined = (t) => (t !== undefined) ? false : true
const isDefined = (t) => isUndefined(t) == false
function isPrivateKeyPemString(value) {
   if (typeof value !== 'string') {
      return false;
   }

   // Check for PEM header and footer lines (case-insensitive)
   // const pemRegex = /^-----BEGIN (?:CERTIFICATE|PUBLIC KEY|PRIVATE KEY|RSA PRIVATE KEY)-----(.*?)-----END (?:CERTIFICATE|PUBLIC KEY|PRIVATE KEY|RSA PRIVATE KEY)-----$/i;
   const pemRegex = /^(-----BEGIN (RSA PRIVATE|PRIVATE) KEY-----\n?(?:[A-Za-z0-9+/=]+\n?)*-----END (RSA PRIVATE|PRIVATE) KEY-----)\n?$/;
   return pemRegex.test(value);
}

function extractKey(asn1) {
   let asn1tocheck = asn1;

   while (true) {
      const types = Defs.commonTypes
         .map(type => {
            const stats = Defs.match(asn1tocheck, type);
            return { type, match: stats.recognized / stats.total };
         })
         .sort((a, b) => b.match - a.match);

      const isMatch = types[0].match == 1

      if (isMatch) {
         delete asn1tocheck.def;
         return { type: types[0].type, key: asn1tocheck }
      }

      if (asn1tocheck.sub.length < 1) throw Error('Key is not found ')
      asn1tocheck = findLargestLengthObject(asn1tocheck.sub);
   }
}

function findLargestLengthObject(arr) {
   let largestObject = null;

   for (const obj of arr) {
      if (obj.hasOwnProperty('length') && (!largestObject || obj.length > largestObject.length)) {
         largestObject = obj;
      }
   }
   delete largestObject.def;
   return largestObject;
}

function merge(...args) {
   let a = new Uint8Array(0), b = a;
   for (const e of args) {
      a = new Uint8Array(e.length + b.length);
      a.set(b);
      a.set(e, b.length);
      b = a;
   };
   return a
}

/**
 * OS2IP converts an octet string to a nonnegative integer.
 * @param {Uint8Array} X 
 * @returns {bigInt}
 */
export function OS2IP(X) {
   // LINK - https://datatracker.ietf.org/doc/html/rfc8017#page-11
   // Check if input is a string
   validate(X, [Uint8Array, Array])

   let x = bigInt(0);
   let len = X.length;

   // Loop through each octet (byte) in the string
   for (let i = 0; i < len; i++) {
      // Get the integer value of the current octet
      const byteValue = X.at(i)//X.charCodeAt(i);

      // Add the octet value shifted by its position to the result
      //x += byteValue * Math.pow(256, len - i - 1);
      x = x.plus(bigInt(byteValue).multiply(bigInt(256).pow(len - i - 1)))
   }

   return x;
}

/**
 * I2OSP converts a nonnegative integer to an octet string of a
   specified length.
 * @param {integer} x 
 * @param {integer} xLen 
 * @returns 
 */
export function I2OSP(x, xLen) {
   return I2OSP_array(x, xLen).map(byteValue => String.fromCharCode(byteValue)).join('');
}
/**
 * 
 * @param {bigInt|integer} x 
 * @param {integer} xLen 
 * @returns 
 */
export function I2OSP_uint8(x, xLen) {
   return new Uint8Array(I2OSP_array(x, xLen))
}
/**
 * 
 * @param {bigInt|integer} x 
 * @param {integer} xLen 
 * @returns {Array}
 */
export function I2OSP_array(x, xLen) { // FIXME - x and xLen must be instanceof bigInt
   // Check if input is a non-negative integer
   let isValid = validate(x, [bigInt, 'number']);
   if (isValid instanceof TypeError) return isValid
   x = bigInt(x);
   if (x.isNegative()) return TypeError('Input x must be a non-negative (big)-integer');
   // Check if xLen is a positive integer
   isValid = validate(xLen, [bigInt, 'number']);
   if (isValid instanceof TypeError) return isValid
   xLen = bigInt(xLen);
   if (xLen.lesserOrEquals(0)) return TypeError('Input xLen must be a positive integer');

   // Check for overflow
   const maxInt = bigInt(256).pow(xLen)//Math.pow(256, xLen);
   if (x.greaterOrEquals(maxInt)) return TypeError('integer too large');

   const octetString = [];
   // Convert integer to base-256 representation (array of digits)
   //for (let i = xLen - 1; i >= 0; i--) {
   for (let i = xLen.minus(1); i.greaterOrEquals(0); i = i.minus(1)) {
      const digit = x.divide(bigInt(256).pow(i));// Math.floor( x / Math.pow(256,i))
      octetString.push(digit);
      //x -= digit * Math.pow(256, i);
      x = x.minus(digit.multiply(bigInt(256).pow(i)))
   };
   return octetString
}
/**
 * 
 * @param {integer} messageInt 
 * @param {{n:bigInt,d:bigInt}} privateKey 
 * @returns {bigInt}
 */
export function RSASP1(messageInt, privateKey) {
   let isValid = validate(messageInt, [bigInt, 'number'])
   if (isValid instanceof TypeError) return isValid

   isValid = validate(privateKey, [{ n: bigInt(0), d: bigInt(0) }])
   if (isValid instanceof TypeError) return isValid

   const { n, d } = privateKey;
   // Step 1: Validate message representative range
   if (bigInt(messageInt).isNegative() || bigInt(messageInt).greaterOrEquals(n)) {
      return TypeError("message representative out of range");
   }

   // Step 2: Signature computation based on key format (n, d)
   return bigInt(messageInt).modPow(d, n);
}

/**
 * 
 * @param {bigInt} signatureBigInt 
 * @param {{n:bigInt,e:bigInt}} publicKey 
 * @returns {bigInt}
 */
export function RSAVP1(signatureBigInt, publicKey) {
   let isValid = validate(signatureBigInt, [bigInt, 'number'])
   if (isValid instanceof TypeError) return isValid

   isValid = validate(publicKey, [{ n: bigInt(0), e: bigInt(0) }])
   if (isValid instanceof TypeError) return isValid

   const { n, e } = publicKey;
   if (bigInt(signatureBigInt).isNegative() || bigInt(signatureBigInt).greaterOrEquals(n)) {
      return TypeError("message representative out of range");
   }
   return bigInt(signatureBigInt).modPow(e, n)
}

function setFirstBitsInFirstOctetsBy0(maskedDb, emLen, emBits) {
   const octets = Math.floor((emLen * 8 - emBits) / 8);
   const bits = (emLen * 8 - emBits) % 8;
   // Create a new Uint8Array of the desired length, filled with zeros
   const newMaskedDb = new Uint8Array(maskedDb.length);
   newMaskedDb.fill(0, 0, octets); // Fill the first 'octets' bytes with zeros

   // Copy the remaining bytes from the original array
   newMaskedDb.set(maskedDb.subarray(octets), octets);

   // Calculate the new byte using bitwise AND operation
   const newByte = maskedDb[octets] & (255 >> bits);

   // Replace the first octet in the new array with the calculated byte
   newMaskedDb[octets] = newByte;

   return newMaskedDb;
}

function checkFirstBitsInFirstOctetsIs0(maskedDb, emLen, emBits) {
   // Calculate octets and bits
   const octets = Math.floor((emLen * 8 - emBits) / 8);
   const bits = (emLen * 8 - emBits) % 8;

   // Create a new Uint8Array for the first 'octets' bytes
   const zero = new Uint8Array(octets);
   if(zero.length==0) return true;
   // Apply bitwise NOT and AND operations to the first octet
   zero[0] = maskedDb[octets] & ~(255 >> bits);

   // Copy remaining bytes from the original array (if any)
   if (octets < maskedDb.length) {
      zero.set(maskedDb.subarray(octets), octets);
   }

   // Check if all bytes in 'zero' are zero
   for (const byte of zero) {
      if (byte !== 0) {
         return false;
      }
   }

   return true;
}

//`esbuild ./index.js --bundle --minify --format=esm --target=esnext --outfile=../dist/RSAKEY.js "--external:npm*" "--external:@*" "--external:https*"`