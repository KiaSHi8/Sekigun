fn main() {
    // Сообщаем Rust, что нужно подтянуть системную библиотеку Windows
    println!("cargo:rustc-link-lib=advapi32");
}
