fn main() {
    println!(r#"cargo:rustc-link-search=native=C:\Npcap-SDK-1.15\Lib\x64"#);
    println!("cargo:rustc-link-lib=Packet");
    println!("cargo:rustc-link-lib=wpcap");
}
