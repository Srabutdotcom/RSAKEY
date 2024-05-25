const baseUrl = import.meta.url;
import jwkToPem from "npm:jwk-to-pem"
import { publicKeyJwk, privateKeyJwk, privateKeyPem, signature} from '../../webcrypto/index.js'
import { RSAKey } from '../src/index.js';

/* const privateKeyPem = jwkToPem(privateKeyJwk, {private:true}); 
const publicKeyPem = jwkToPem(publicKeyJwk)
 */
export const asn1Key = new RSAKey(privateKeyPem, {sha:256, saltLength:0});

const msg = new Uint8Array([1, 4, 5, 6]);

const sign = asn1Key.RSASSA_PSS_SIGN(msg);
const verify = asn1Key.RSASSA_PSS_VERIFY({n:asn1Key.n, e:asn1Key.e},msg, sign);

const signFromWeb = new Uint8Array(signature);

const verifyWebSign = asn1Key.RSASSA_PSS_VERIFY({n:asn1Key.n, e:asn1Key.e},msg, signFromWeb);debugger;

function base64urlToUint8Array(base64url) {
   // Replace base64url-specific characters
   const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');

   // Decode Base64 to binary data
   const binaryString = atob(base64);
   const uint8Array = new Uint8Array(binaryString.length);
   for (let i = 0; i < binaryString.length; i++) {
       uint8Array[i] = binaryString.charCodeAt(i);
   }

   return uint8Array;
}

const nInPKJwk = base64urlToUint8Array(privateKeyJwk.n)
const nInAsn1 = asn1Key.nUint8

debugger;