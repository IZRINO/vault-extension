use crate::bitwarden::SecretJson;
use crate::portable::{INVALID, LIMIT, MAX_ROWS, MappingError};
use serde::{Deserializer, de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor}};
use serde_json::{Map, Number, Value, json};
use std::{cell::Cell, fmt};
use zeroize::Zeroizing;

const MAX_VALUES: usize = 1_000_000;
const MAX_FIELDS: usize = 256;

struct Strict<'a>(&'a Cell<usize>);

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = SecretJson;

    fn deserialize<D: Deserializer<'de>>(self, reader: D) -> Result<Self::Value, D::Error> {
        let remaining = self.0.get().checked_sub(1).ok_or_else(|| de::Error::custom(INVALID))?;
        self.0.set(remaining);
        reader.deserialize_any(self)
    }
}

// serde_json's default Value deserializer keeps the last key, even for security flags.
impl<'de> Visitor<'de> for Strict<'_> {
    type Value = SecretJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without repeated object keys")
    }
    fn visit_unit<E: de::Error>(self) -> Result<SecretJson, E> { Ok(SecretJson(Value::Null)) }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<SecretJson, E> { Ok(SecretJson(Value::Bool(value))) }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<SecretJson, E> { Ok(SecretJson(Value::from(value))) }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<SecretJson, E> { Ok(SecretJson(Value::from(value))) }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<SecretJson, E> {
        Number::from_f64(value).map(|num| SecretJson(Value::Number(num))).ok_or_else(|| E::custom(INVALID))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<SecretJson, E> { self.visit_string(value.to_owned()) }
    fn visit_string<E: de::Error>(self, value: String) -> Result<SecretJson, E> { Ok(SecretJson(Value::String(value))) }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<SecretJson, S::Error> {
        let mut secret = SecretJson(Value::Array(Vec::new()));
        let values = secret.0.as_array_mut().unwrap();
        while let Some(mut value) = seq.next_element_seed(Strict(self.0))? {
            if values.len() == MAX_ROWS { return Err(de::Error::custom(INVALID)); }
            values.push(std::mem::take(&mut value.0));
        }
        Ok(secret)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<SecretJson, M::Error> {
        let mut secret = SecretJson(Value::Object(Map::new()));
        let fields = secret.0.as_object_mut().unwrap();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 512 || fields.len() == MAX_FIELDS || fields.contains_key(&key) {
                return Err(de::Error::custom(INVALID));
            }
            let mut value = map.next_value_seed(Strict(self.0))?;
            fields.insert(key, std::mem::take(&mut value.0));
        }
        Ok(secret)
    }
}

pub(crate) fn read(bytes: &[u8]) -> Result<SecretJson, MappingError> {
    if bytes.is_empty() || bytes.len() > LIMIT { return Err(INVALID); }
    let mut decoder = serde_json::Deserializer::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes));
    let document = Strict(&Cell::new(MAX_VALUES)).deserialize(&mut decoder).map_err(|_| INVALID)?;
    decoder.end().map_err(|_| INVALID)?;
    Ok(document)
}

pub(crate) fn fields(value: &Value) -> Result<SecretJson, MappingError> {
    let raw = Zeroizing::new(value.to_string());
    if raw.len() > 128 * 1024 { return Err(INVALID); }
    Ok(SecretJson(json!([{ "name":"厂商 JSON 源字段", "value":&*raw, "hidden":true }])))
}
