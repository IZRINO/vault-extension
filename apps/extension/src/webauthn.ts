type PrfExtensions = AuthenticationExtensionsClientInputs & { prf: { eval: { first: Uint8Array<ArrayBuffer> } } };
type PrfResults = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first: ArrayBuffer } } };
const random = () => crypto.getRandomValues(new Uint8Array(32));
export async function readPrf(credentialId: number[], salt: number[]): Promise<number[]> {
  const credential = await navigator.credentials.get({ publicKey: {
    challenge: random(), allowCredentials: [{ id: new Uint8Array(credentialId), type: 'public-key' }],
    userVerification: 'required', timeout: 60000,
    extensions: { prf: { eval: { first: new Uint8Array(salt) } } } as PrfExtensions,
  } }) as PublicKeyCredential | null;
  const result = (credential?.getClientExtensionResults() as PrfResults | undefined)?.prf?.results?.first;
  if (!result || result.byteLength !== 32) throw new Error('此设备未返回 PRF 密钥，无法启用系统解锁，请使用本地 PIN。');
  const bytes = new Uint8Array(result);
  const output = Array.from(bytes);
  bytes.fill(0);
  return output;
}
export async function registerPrf() {
  if (!window.PublicKeyCredential || !await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
    throw new Error('此浏览器没有可用的系统认证器，请使用本地 PIN。');
  }
  const salt = Array.from(random());
  const credential = await navigator.credentials.create({ publicKey: {
    challenge: random(), rp: { name: 'Vault 本地密码库' },
    user: { id: random(), name: 'local-vault', displayName: '本机密码库' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    timeout: 60000, attestation: 'none',
    extensions: { prf: { eval: { first: new Uint8Array(salt) } } } as PrfExtensions,
  } }) as PublicKeyCredential | null;
  if (!credential) throw new Error('系统解锁注册已取消。');
  const credentialId = Array.from(new Uint8Array(credential.rawId));
  const output = await readPrf(credentialId, salt);
  const repeated = await readPrf(credentialId, salt);
  const deterministic = output.every((value, index) => value === repeated[index]);
  repeated.fill(0);
  if (!deterministic) { output.fill(0); throw new Error('PRF 自检结果不一致，请使用本地 PIN。'); }
  return { credentialId, salt, output };
}
