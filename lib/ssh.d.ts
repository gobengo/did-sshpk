import { ISigner } from "./types.js";
import type sshpk from "sshpk";
export declare class SshpkSigner implements ISigner {
    #private;
    static fromPrivateKey(key: sshpk.PrivateKey): Promise<SshpkSigner>;
    constructor(key: sshpk.PrivateKey, options?: {
        id: string;
    });
    get publicKeyMultibase(): string;
    get id(): string;
    sign(signable: {
        data: Uint8Array;
    }): Promise<Uint8Array>;
}
/**
 * WebCrypto exportKey pkcs8 is just the raw DER.
 * If we base64 it and wrap in the right header/footer, it is PEM
 * that can be parsed using sshpk.parsePrivateKey
 * @param pkcs8 - DER encoded pkcs8 buffer
 * @returns PEM private key string
 */
export declare function createPemFromPkcs8Der(pkcs8: ArrayBuffer): string;
//# sourceMappingURL=ssh.d.ts.map