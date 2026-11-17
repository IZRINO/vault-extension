use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn decode(bytes: Vec<u8>, width: u32, height: u32) -> Result<String, &'static str> {
    let bytes = Zeroizing::new(bytes);
    let size = (width as usize).checked_mul(height as usize).ok_or("截图过大。")?;
    if width < 21 || height < 21 || width > 8192 || height > 8192 || size > 16_777_216 || bytes.len() != size {
        return Err("截图尺寸无效或超过 1600 万像素。");
    }
    let mut results = Vec::new();
    for inverted in [false, true] {
        let mut image = rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize,
            |x, y| { let value = bytes[y * width as usize + x]; if inverted { 255 - value } else { value } });
        for grid in image.detect_grids().into_iter().take(32) {
            if let Ok((_, text)) = grid.decode() {
                let text = Zeroizing::new(text);
                if !text.starts_with("otpauth://") { continue; }
                if let Ok(otp) = vault_otp::parse(&text) {
                    let uri = otp.canonical_uri();
                    if !results.contains(&*uri) { results.push(uri.to_string()); }
                }
            }
        }
        if !results.is_empty() { break; }
    }
    let results = Zeroizing::new(results);
    serde_json::to_string(&*results).map_err(|_| "二维码读取失败。")
}

#[wasm_bindgen]
pub fn wasm_scan_otp(bytes: Vec<u8>, width: u32, height: u32) -> Result<String, JsValue> {
    decode(bytes, width, height).map_err(JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_sizes_and_ignores_empty_screen() {
        assert!(decode(vec![0; 10], 200, 200).is_err());
        assert!(decode(Vec::new(), u32::MAX, u32::MAX).is_err());
        assert_eq!(decode(vec![255; 80 * 80], 80, 80).unwrap(), "[]");
    }
}
