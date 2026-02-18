fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        // Ensure you have an 'icon.ico' file in the same folder
        res.set_icon("icon.ico"); 
        res.compile().unwrap();
    }
}
