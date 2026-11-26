import type { Proof } from '../vault-messages';

export type PasskeyRequest = {
  kind: 'register' | 'assert';
  rpId?: string;
  challenge: string;
  credentialIds: string[];
  algorithms: number[];
  user?: { id: string; name: string; display: string };
  uv: 'discouraged' | 'preferred' | 'required';
  conditional: boolean;
  resident: boolean;
  credProps: boolean;
};
export type TrustedRequest = PasskeyRequest & { origin: string; rpId: string };
export type PasskeyCandidate = { itemId: string; id: string | null; title: string; account: string; verify: boolean; suspended: boolean };
export type PasskeySelection = { itemId?: string; credentialId?: string; increment?: boolean; proof?: Proof };
export type PasskeyReply = {
  id: string;
  clientDataJson: string;
  authenticatorData: string;
  attestationObject?: string;
  publicKey?: string;
  publicKeyAlgorithm?: number;
  signature?: string;
  userHandle?: string;
};
type AlreadyRegistered = { type: 'already-registered' };
export type PasskeyResolution = { type: 'answer'; value: PasskeyReply } | AlreadyRegistered;
export type PasskeyPerformResult = { type: 'answer'; reply: string; head: number[]; snap: number[] } | AlreadyRegistered;
export type PasskeyOutcome = { type: 'native' | 'cancel' } | PasskeyResolution;
export const PASSKEY_CHANNEL = 'vault-passkey-v1';
export const PASSKEY_PORT = 'vault-passkey-request';

function bytes(value: string | BufferSource) {
  if (typeof value === 'string') throw new TypeError('Expected binary WebAuthn data');
  const view = ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : new Uint8Array(value);
  if (!view.byteLength || view.byteLength > 1024) throw new RangeError('Unsupported WebAuthn data length');
  return btoa(String.fromCharCode(...view)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function normalizeRequest(kind: PasskeyRequest['kind'], options: CredentialCreationOptions | CredentialRequestOptions | undefined): PasskeyRequest | undefined {
  const pk = options?.publicKey;
  if (!pk || !window.isSecureContext) return;
  const request = options as CredentialRequestOptions;
  const assertion = pk as PublicKeyCredentialRequestOptions;
  const registration = pk as PublicKeyCredentialCreationOptions;
  const conditional = request.mediation === 'conditional';
  if (request.mediation && !['optional', 'required', 'conditional'].includes(request.mediation)) return;
  if (conditional && kind === 'register') return;
  if (registration.attestation && registration.attestation !== 'none') return;
  if (registration.authenticatorSelection?.authenticatorAttachment === 'cross-platform') return;
  const hints = (pk as typeof pk & { hints?: string[] }).hints;
  if (hints?.some(hint => hint === 'security-key' || hint === 'hybrid')) return;
  if (pk.extensions && Object.keys(pk.extensions).some(key => key !== 'credProps' || kind !== 'register')) return;
  const credentialDescriptors = kind === 'register' ? registration.excludeCredentials : assertion.allowCredentials;
  if (credentialDescriptors?.some(descriptor => descriptor.type !== 'public-key') || (credentialDescriptors?.length ?? 0) > 64) return;
  const algorithms = kind === 'register'
    ? registration.pubKeyCredParams?.filter(param => param.type === 'public-key').map(param => param.alg) ?? [] : [];
  if (kind === 'register' && (!registration.rp || !registration.user || !algorithms.some(alg => alg === -7 || alg === -8))) return;
  const uv = (kind === 'register' ? registration.authenticatorSelection?.userVerification : assertion.userVerification) ?? 'preferred';
  const residentKey = registration.authenticatorSelection?.residentKey;
  const resident = kind === 'register' && (residentKey ? residentKey !== 'discouraged' : registration.authenticatorSelection?.requireResidentKey !== false);
  return {
    kind, rpId: kind === 'register' ? registration.rp.id : assertion.rpId, conditional, uv, resident,
    challenge: bytes(pk.challenge), credentialIds: (credentialDescriptors ?? []).map(entry => bytes(entry.id)),
    algorithms, credProps: registration.extensions?.credProps === true,
    user: kind === 'register'
      ? { id: bytes(registration.user.id), name: registration.user.name, display: registration.user.displayName } : undefined,
  };
}

const wireBytes = (value: unknown, min: number, max: number): value is string =>
  typeof value === 'string' && value.length >= min && value.length <= max && /^[A-Za-z0-9_-]+$/.test(value);
export function readRequest(input: unknown): PasskeyRequest | undefined {
  if (!input || typeof input !== 'object') return;
  const { kind, rpId, challenge, credentialIds, algorithms, user, uv, conditional, resident, credProps } = input as PasskeyRequest;
  if ((kind !== 'register' && kind !== 'assert') ||
      (rpId !== undefined && (typeof rpId !== 'string' || rpId.length > 253 || !/^[a-z0-9.-]+$/.test(rpId))) ||
      !wireBytes(challenge, 22, 1366) || !Array.isArray(credentialIds) || credentialIds.length > 64 ||
      !credentialIds.every(id => wireBytes(id, 2, 1364)) || !Array.isArray(algorithms) || algorithms.length > 32 ||
      !algorithms.every(alg => Number.isSafeInteger(alg) && alg >= -65536 && alg <= 65536) ||
      !['discouraged', 'preferred', 'required'].includes(uv) || typeof conditional !== 'boolean' ||
      typeof resident !== 'boolean' || typeof credProps !== 'boolean') return;
  if (kind === 'assert') return { kind, rpId, challenge, credentialIds, algorithms: [], uv, conditional, resident: false, credProps: false };
  if (conditional || !user || !wireBytes(user.id, 2, 86) || typeof user.name !== 'string' || !user.name || user.name.length > 1024 ||
      typeof user.display !== 'string' || user.display.length > 1024 || !algorithms.some(alg => alg === -7 || alg === -8)) return;
  return { kind, rpId, challenge, credentialIds, algorithms, uv, conditional, resident, credProps,
    user: { id: user.id, name: user.name, display: user.display } };
}

export function browserCredential(result: PasskeyReply, request: PasskeyRequest): PublicKeyCredential {
  const buffer = (value: string) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)).buffer;
  const register = request.kind === 'register';
  const response = Object.create(register ? AuthenticatorAttestationResponse.prototype : AuthenticatorAssertionResponse.prototype);
  const define = (target: object, fields: Record<string, unknown>) => Object.defineProperties(target,
    Object.fromEntries(Object.entries(fields).map(([name, value]) => [name, { value, configurable: true }])));
  const authData = buffer(result.authenticatorData);
  const clientDataJSON = buffer(result.clientDataJson);
  const ext = () => request.credProps ? { credProps: { rk: request.resident } } : {};
  const encoded: Record<string, unknown> = { clientDataJSON: result.clientDataJson, authenticatorData: result.authenticatorData };
  if (register) {
    Object.assign(encoded, { attestationObject: result.attestationObject, publicKey: result.publicKey,
      publicKeyAlgorithm: result.publicKeyAlgorithm, transports: ['internal'] });
    define(response, { clientDataJSON, attestationObject: buffer(result.attestationObject!),
      getAuthenticatorData: () => authData.slice(0), getPublicKey: () => buffer(result.publicKey!),
      getPublicKeyAlgorithm: () => result.publicKeyAlgorithm, getTransports: () => ['internal'] });
  } else {
    Object.assign(encoded, { signature: result.signature, ...(result.userHandle ? { userHandle: result.userHandle } : {}) });
    define(response, { clientDataJSON, authenticatorData: authData, signature: buffer(result.signature!),
      userHandle: result.userHandle ? buffer(result.userHandle) : null });
  }
  const credential: PublicKeyCredential = Object.create(PublicKeyCredential.prototype);
  define(credential, { id: result.id, rawId: buffer(result.id), type: 'public-key', response,
    authenticatorAttachment: 'platform', getClientExtensionResults: ext,
    toJSON: () => ({ id: result.id, rawId: result.id, type: 'public-key', authenticatorAttachment: 'platform',
      clientExtensionResults: ext(), response: { ...encoded, ...(register ? { transports: ['internal'] } : {}) } }),
  });
  return credential;
}
