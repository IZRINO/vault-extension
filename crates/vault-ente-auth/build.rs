fn main() {
    if std::env::var("TARGET").is_ok_and(|target| target == "wasm32-unknown-unknown") {
        // Ente Auth's desktop exporter defaults to a 1 GiB Argon2id workspace.
        // Leave 64 MiB for this worker's runtime and bounded text/JSON handling.
        println!("cargo:rustc-link-arg-cdylib=--max-memory=1140850688");
    }
}
