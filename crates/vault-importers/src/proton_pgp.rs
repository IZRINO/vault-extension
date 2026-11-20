use pgp::{
    armor::Dearmor,
    composed::{Edata, Esk, Message},
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{ProtectedDataConfig, SymKeyEncryptedSessionKey, SymEncryptedProtectedDataConfig},
    types::{Password, StringToKey},
};
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

use crate::portable::{LIMIT, MappingError};

const DAMAGED: MappingError = "Proton Pass PGP 文件密码错误或数据已损坏。";
const UNSUPPORTED: MappingError = "不支持该 Proton Pass PGP 加密版本或参数。";

pub(crate) fn decrypt(armor: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, MappingError> {
    if password.is_empty() { return Err("请输入 Proton Pass 导出时设置的 PGP 文件密码。"); }
    if !armor.starts_with(b"-----BEGIN PGP MESSAGE-----") { return Err(DAMAGED); }
    let mut binary = Zeroizing::new(Vec::new());
    Dearmor::new(Cursor::new(armor)).take(LIMIT as u64 + 1).read_to_end(&mut binary).map_err(|_| DAMAGED)?;
    if binary.len() > LIMIT { return Err("Proton Pass PGP 数据超过大小上限。"); }
    // An official envelope starts with one short v4 SKESK and then SEIPD.
    // Reject additional key packets before the generic parser could collect them.
    let [0xc3, size @ 13..=46, 4, ..] = binary.as_slice() else { return Err(UNSUPPORTED); };
    if binary.get(2 + usize::from(*size)) != Some(&0xd2) { return Err(UNSUPPORTED); }
    let message = Message::from_bytes(Cursor::new(binary.as_slice())).map_err(|_| DAMAGED)?;
    let Message::Encrypted { esk, edata: Edata::SymEncryptedProtectedData { reader }, .. } = &message
        else { return Err(UNSUPPORTED); };
    let [Esk::SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey::V4 {
        sym_algorithm: SymmetricKeyAlgorithm::AES128 | SymmetricKeyAlgorithm::AES192 | SymmetricKeyAlgorithm::AES256,
        s2k: StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512, ..
        },
        ..
    })] = esk.as_slice() else { return Err(UNSUPPORTED); };
    if !matches!(reader.config(), ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1)) {
        return Err(UNSUPPORTED);
    }
    // The producer uses a single iterated S2K (maximum 65,011,712 bytes) and MDC.
    // rPGP checks the MDC before releasing SEIPDv1 plaintext, not in streaming mode.
    let plaintext = message.decrypt_with_password(&Password::from(password)).map_err(|_| DAMAGED)?;
    if !plaintext.is_literal() { return Err(UNSUPPORTED); }
    let mut decoded = Zeroizing::new(Vec::new());
    plaintext.take(LIMIT as u64 + 1).read_to_end(&mut decoded).map_err(|_| DAMAGED)?;
    if decoded.len() > LIMIT { return Err("Proton Pass PGP 解密结果超过大小上限。"); }
    Ok(decoded)
}
