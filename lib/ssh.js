var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _SshpkSigner_sk;
import { encodeEd25519PublicKeyMultibase } from "@did.coop/did-key-ed25519/multibase";
export class SshpkSigner {
    static async fromPrivateKey(key) {
        return new SshpkSigner(key);
    }
    constructor(key, options) {
        _SshpkSigner_sk.set(this, void 0);
        __classPrivateFieldSet(this, _SshpkSigner_sk, key, "f");
    }
    get publicKeyMultibase() {
        const publicKey = __classPrivateFieldGet(this, _SshpkSigner_sk, "f").toPublic();
        const publicKeyPkcs8Pem = publicKey.toString('pkcs8');
        const publicKeyPkcs8Base64 = publicKeyPkcs8Pem.split('\n').filter(l => !l.startsWith('--')).join('');
        const publicKeyPkcs8 = Buffer.from(publicKeyPkcs8Base64, 'base64');
        if (publicKeyPkcs8.byteLength !== 44)
            throw new Error(`unable to parse spki publicKey`);
        const publicKeyRaw = publicKeyPkcs8.slice(publicKeyPkcs8.byteLength - 32);
        const publicKeyMultibase = encodeEd25519PublicKeyMultibase(publicKeyRaw);
        return publicKeyMultibase;
    }
    get id() {
        const publicKeyMultibase = this.publicKeyMultibase;
        const verificationMethodId = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
        return verificationMethodId;
    }
    async sign(signable) {
        const signing = __classPrivateFieldGet(this, _SshpkSigner_sk, "f").createSign('sha512');
        signing.update(Buffer.from(signable.data));
        const signature = signing.sign();
        const bytes = new Uint8Array(signature.toBuffer());
        return bytes;
    }
}
_SshpkSigner_sk = new WeakMap();
/**
 * WebCrypto exportKey pkcs8 is just the raw DER.
 * If we base64 it and wrap in the right header/footer, it is PEM
 * that can be parsed using sshpk.parsePrivateKey
 * @param pkcs8 - DER encoded pkcs8 buffer
 * @returns PEM private key string
 */
export function createPemFromPkcs8Der(pkcs8) {
    const base64Der = btoa(new Uint8Array(pkcs8)
        .reduce((data, byte) => data + String.fromCharCode(byte), ''));
    const pem = [
        '-----BEGIN PRIVATE KEY-----',
        base64Der,
        '-----END PRIVATE KEY-----',
    ].join('\n');
    return pem;
}
