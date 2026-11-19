fn main() {
    if std::env::var("TARGET").is_ok_and(|target| target == "wasm32-unknown-unknown") {
        // The disposable worker also bounds the memory used by third-party unpackers and XML.
        println!("cargo:rustc-link-arg-cdylib=--max-memory=268435456");
    }
}
