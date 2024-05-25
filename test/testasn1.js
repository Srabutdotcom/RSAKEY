const baseUrl = import.meta.url;
import { RSAKey } from '../src/index.js';

const pemKey = Deno.readTextFileSync(new URL('../../jwk/privateKey.pem',baseUrl));

const asn1Key = new RSAKey(pemKey, {sha:256, saltLength:0});

const msg = new Uint8Array([1, 4, 5, 6]);

const sign = asn1Key.RSASSA_PSS_SIGN(msg);
// '144,71,125,213,29,120,189,48,105,45,247,237,62,82,229,7,101,80,209,100,251,109,145,141,114,165,3,66,173,145,23,4,87,9,86,186,141,229,2,100,209,159,134,55,135,197,242,196,177,186,109,82,78,185,254,232,64,93,45,204,90,9,171,25,247,122,10,99,22,185,94,43,92,247,114,33,140,15,158,161,231,10,27,67,116,162,15,185,54,28,111,146,35,57,19,177,176,139,101,165,90,170,242,152,162,102,75,46,75,67,111,165,39,194,42,120,134,159,204,192,250,161,125,227,180,9,148,167'

const verify = asn1Key.RSASSA_PSS_VERIFY({n:asn1Key.n, e:asn1Key.e},msg, sign);debugger;