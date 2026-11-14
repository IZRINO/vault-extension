type Otp = typeof import('../../../crates/vault-otp/pkg/vault_otp.js');
let ready: Promise<Otp> | undefined;

export function loadVaultOtp(): Promise<Otp> {
  ready ??= import('../../../crates/vault-otp/pkg/vault_otp.js').then(async otp => {
    await otp.default();
    return otp;
  }).catch(error => { ready = undefined; throw error; });
  return ready;
}
