// LINK - https://pypi.org/project/pkcs1/
import bigInt from 'npm:big-integer'
import { RSAKey } from '../src/index.js';
import { hexToBase64Url } from '../../utils/index.js'
import { Key } from 'npm:js-crypto-key-utils';

// modulus
const modHex = `a2 ba 40 ee 07 e3 b2 bd 2f 02 ce 22 7f 36 a1 95 02 44 86 e4 9c 19 cb 41 
bb bd fb ba 98 b2 2b 0e 57 7c 2e ea ff a2 0d 88 3a 76 e6 5e 39 4c 69 d4 
b3 c0 5a 1e 8f ad da 27 ed b2 a4 2b c0 00 fe 88 8b 9b 32 c2 2d 15 ad d0 
cd 76 b3 e7 93 6e 19 95 5b 22 0d d1 7d 4e a9 04 b1 ec 10 2b 2e 4d e7 75 
12 22 aa 99 15 10 24 c7 cb 41 cc 5e a2 1d 00 ee b4 1f 7c 80 08 34 d2 c6 
e0 6b ce 3b ce 7e a9 a5`
const n = bigInt(modHex.split(/\s/).filter(e => e.length).join(''), 16);

// public exponent
const e = bigInt(`01 00 01`.split(/\s/).filter(e => e.length).join(''), 16)

// private exponent
const expHex = `05 0e 2c 3e 38 d8 86 11 02 88 df c6 8a 95 33 e7 e1 2e 27 d2 aa 56 d2 cd 
b3 fb 6e fa 99 0b cf f2 9e 1d 29 87 fb 71 19 62 86 0e 73 91 b1 ce 01 eb 
ad b9 e8 12 d2 fb df af 25 df 4a e2 61 10 a6 d7 a2 6f 0b 81 0f 54 87 5e 
17 dd 5c 9f b6 d6 41 76 12 45 b8 1e 79 f8 c8 8f 0e 55 a6 dc d5 f1 33 ab 
d3 5f 8f 4e c8 0a df 1b f8 62 77 a5 82 89 4c b6 eb cd 21 62 f1 c7 53 4f 
1f 49 47 b1 29 15 1b 71`
const d = bigInt(expHex.split(/\s/).filter(e => e.length).join(''), 16);

// prime 1
const pHex = `d1 7f 65 5b f2 7c 8b 16 d3 54 62 c9 05 cc 04 a2 6f 37 e2 a6 7f a9 c0 ce 
0d ce d4 72 39 4a 0d f7 43 fe 7f 92 9e 37 8e fd b3 68 ed df f4 53 cf 00 
7a f6 d9 48 e0 ad e7 57 37 1f 8a 71 1e 27 8f 6b`

// prime 2
const qHex = `c6 d9 2b 6f ee 74 14 d1 35 8c e1 54 6f b6 29 87 53 0b 90 bd 15 e0 f1 49 
63 a5 e2 63 5a db 69 34 7e c0 c0 1b 2a b1 76 3f d8 ac 1a 59 2f b2 27 57 
46 3a 98 24 25 bb 97 a3 a4 37 c5 bf 86 d0 3f 2f`

// dp
const dpHex = `9d 0d bf 83 e5 ce 9e 4b 17 54 dc d5 cd 05 bc b7 b5 5f 15 08 33 0e a4 9f 
14 d4 e8 89 55 0f 82 56 cb 5f 80 6d ff 34 b1 7a da 44 20 88 53 57 7d 08 
e4 26 28 90 ac f7 52 46 1c ea 05 54 76 01 bc 4f`

// dq 
const dqHex = `12 91 a5 24 c6 b7 c0 59 e9 0e 46 dc 83 b2 17 1e b3 fa 98 81 8f d1 79 b6 
c8 bf 6c ec aa 47 63 03 ab f2 83 fe 05 76 9c fc 49 57 88 fe 5b 1d df de 
9e 88 4a 3c d5 e9 36 b7 e9 55 eb f9 7e b5 63 b1`

// qi 
const qiHex = `a6 3f 1d a3 8b 95 0c 9a d1 c6 7c e0 d6 77 ec 29 14 cd 7d 40 06 2d f4 2a 
67 eb 19 8a 17 6f 97 42 aa c7 c5 fe a1 4f 22 97 66 2b 84 81 2c 4d ef c4 
9a 80 25 ab 43 82 28 6b e4 c0 37 88 dd 01 d6 9f`

// message 
const msg = new Uint8Array(`85 9e ef 2f d7 8a ca 00 30 8b dc 47 11 93 bf 55 bf 9d 78 db 8f 8a 67 2b 
48 46 34 f3 c9 c2 6e 64 78 ae 10 26 0f e0 dd 8c 08 2e 53 a5 29 3a f2 17 
3c d5 0c 6d 5d 35 4f eb f7 8b 26 02 1c 25 c0 27 12 e7 8c d4 69 4c 9f 46 
97 77 e4 51 e7 f8 e9 e0 4c d3 73 9c 6b bf ed ae 48 7f b5 56 44 e9 ca 74 
ff 77 a5 3c b7 29 80 2f 6e d4 a5 ff a8 ba 15 98 90 fc`.split(/\s/).filter(e => e.length).map(e => Number('0x' + e)));

const salt = new Uint8Array(`e3 b5 d5 d0 02 c1 bc e5 0c 2b 65 ef 88 a1 88 d8 3b ce 7e 61`.split(/\s/).filter(e => e.length).map(e => Number('0x' + e)))

const privateKeyJWK = {
   kty: 'RSA',
   n: hexToBase64Url(modHex),
   d: hexToBase64Url(expHex),
   e: "AQAB",
   p: hexToBase64Url(pHex),
   q: hexToBase64Url(qHex),
   dp: hexToBase64Url(dpHex),
   dq: hexToBase64Url(dqHex),
   qi: hexToBase64Url(qiHex)
}

const publicKeyObj = { n, e }
const publicKeyJWK = {
   kty: 'RSA',
   n: hexToBase64Url(modHex),
   e: "AQAB",
}

const keyObj = new Key('jwk', privateKeyJWK);
const privatePem = await keyObj.export('pem');

const asn1Key = new RSAKey(privatePem, { sha: 256, saltLength : 0 });

// check n and d
const nCheck = asn1Key.nUint8
const dCheck = asn1Key.component('d')

// emsa pss encode
const em = asn1Key.EMSA_PSS_ENCODE(msg)

const verifyEm = asn1Key.EMSA_PSS_VERIFY(msg, em)

const sign = asn1Key.RSASSA_PSS_SIGN(msg)

const verifySign = asn1Key.RSASSA_PSS_VERIFY(publicKeyObj, msg, sign)//PASSED - verifySign = 'valid signature'

// check using web crypto api
const privateKeyWeb = await self.crypto.subtle.importKey("jwk", privateKeyJWK, { name: "RSA-PSS", hash: "SHA-256" }, true, ['sign'])

const publicKeyWeb = await self.crypto.subtle.importKey("jwk", publicKeyJWK, { name: "RSA-PSS", hash: "SHA-256" }, true, ['verify'])
const signWeb = await self.crypto.subtle.sign(
   {
      name: "RSA-PSS",
      saltLength: 0, //the length of the salt
   },
   privateKeyWeb, //from generateKey or importKey above
   msg
)

const verifysignWeb = await self.crypto.subtle.verify( // PASSED - verifysignWeb = true
   {
      name: "RSA-PSS",
      saltLength: 0, //the length of the salt
   },
   publicKeyWeb, //from generateKey or importKey above
   signWeb, //ArrayBuffer of the data
   msg
)

//PASSED - all passed