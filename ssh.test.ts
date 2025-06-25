import { test } from "node:test"
import { ISigner } from "./types.js"
import { createPemFromPkcs8Der, SshpkSigner } from "./ssh.js"
import sshpk from "sshpk"
import assert from "node:assert"

const exampleOpenSshPrivateKey = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDA9/3tHALXmc/uyFfZwl4xCz2LdvppkVp6luhxmLygvAAAAJgpYw4tKWMO
LQAAAAtzc2gtZWQyNTUxOQAAACDA9/3tHALXmc/uyFfZwl4xCz2LdvppkVp6luhxmLygvA
AAAECCCt3rR2R2mDmuV56+Qg653nCHF8Xvg0QHdYPm5dicXcD3/e0cAteZz+7IV9nCXjEL
PYt2+mmRWnqW6HGYvKC8AAAAEWJlbmdvQGJlbmdvLmxvY2FsAQIDBA==
-----END OPENSSH PRIVATE KEY-----
`

await test('can parse openssh private key into signer', async t => {
  const privateKey = sshpk.parsePrivateKey(exampleOpenSshPrivateKey)
  const signer: ISigner = await SshpkSigner.fromPrivateKey(privateKey)
  assert.equal(signer.id, `did:key:z6MksSXead72tsxi761DJEzsMCdBiUi7CNkT9HiZw4r3x9aB#z6MksSXead72tsxi761DJEzsMCdBiUi7CNkT9HiZw4r3x9aB`)
})

await test('SshpkSigner produces same signature as webcrypto api', async () => {
  const challenge = new TextEncoder().encode(crypto.randomUUID())

  const keyPairA = await crypto.subtle.generateKey('Ed25519', true, ['sign'])
  // console.debug('keyPairA', keyPairA)
  if (!('privateKey' in keyPairA)) throw new Error("expected keyPairA to have privateKey")
  const keyPairAChallengeSignature = await crypto.subtle.sign('Ed25519', keyPairA.privateKey, challenge)

  const expectedEmptyStringSignature = new Uint8Array(keyPairAChallengeSignature)

  // create a signer from keyPairA exported as pkcs8 der
  const keyPairAExportedToPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPairA.privateKey)
  const keyPairAPkcs8Der = createPemFromPkcs8Der(keyPairAExportedToPkcs8)
  const keyPairASshpkPrivateKey = sshpk.parsePrivateKey(keyPairAPkcs8Der, 'pem')
  const keyPairASshpkSigner = await SshpkSigner.fromPrivateKey(keyPairASshpkPrivateKey)
  const keyPairASshpkSignerSignedChallenge = await keyPairASshpkSigner.sign({ data: challenge })

  assert.deepEqual(keyPairASshpkSignerSignedChallenge, expectedEmptyStringSignature)

  // import using webcrypto
  const imported = await crypto.subtle.importKey(
    'pkcs8',
    keyPairAExportedToPkcs8,
    'Ed25519',
    true,
    ['sign'],
  )
  assert.equal(imported.algorithm.name, 'Ed25519')
})
