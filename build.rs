fn main() {
    println!(
        "cargo:include={}",
        std::env::current_dir().unwrap().display()
    );
    println!("cargo:rerun-if-changed=dns_sd.h");

    println!("cargo:rustc-link-lib=dylib=dns_sd");
}
