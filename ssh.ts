import { ISigner } from "./types.js";
import type sshpk from "sshpk"
import { encodeEd25519PublicKeyMultibase } from "@did.coop/did-key-ed25519/multibase"

export class SshpkSigner implements ISigner {
  #sk: sshpk.PrivateKey
  static async fromPrivateKey(key: sshpk.PrivateKey) {
    return new SshpkSigner(key)
  }
  constructor(key: sshpk.PrivateKey, options?: { id: string }) {
    this.#sk = key
  }
  get publicKeyMultibase() {
    const publicKey = this.#sk.toPublic()
    const publicKeyPkcs8Pem = publicKey.toString('pkcs8')
    const publicKeyPkcs8Base64 = publicKeyPkcs8Pem.split('\n').filter(l => !l.startsWith('--')).join('')
    const publicKeyPkcs8 = Buffer.from(publicKeyPkcs8Base64, 'base64')
    if (publicKeyPkcs8.byteLength !== 44) throw new Error(`unable to parse spki publicKey`)
    const publicKeyRaw = publicKeyPkcs8.slice(publicKeyPkcs8.byteLength-32)
    const publicKeyMultibase = encodeEd25519PublicKeyMultibase(publicKeyRaw)
    return publicKeyMultibase
  }
  get id (): string {
    const publicKeyMultibase = this.publicKeyMultibase
    const verificationMethodId = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
    return verificationMethodId
  }
  async sign(signable: { data: Uint8Array; }): Promise<Uint8Array> {
    const signing = this.#sk.createSign('sha512')
    signing.update(Buffer.from(signable.data))
    const signature = signing.sign()
    const bytes = new Uint8Array(signature.toBuffer())
    return bytes
  }
}

/**
 * WebCrypto exportKey pkcs8 is just the raw DER.
 * If we base64 it and wrap in the right header/footer, it is PEM
 * that can be parsed using sshpk.parsePrivateKey
 * @param pkcs8 - DER encoded pkcs8 buffer
 * @returns PEM private key string
 */
export function createPemFromPkcs8Der(pkcs8: ArrayBuffer): string {
  const base64Der = btoa(
    new Uint8Array(pkcs8)
      .reduce((data, byte) => data + String.fromCharCode(byte), '')
  )
  const pem = [
    '-----BEGIN PRIVATE KEY-----',
    base64Der,
    '-----END PRIVATE KEY-----',
  ].join('\n')
  return pem
}
