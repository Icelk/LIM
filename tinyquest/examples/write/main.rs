use std::fs::File;

fn main() {
    tinyquest::get("alligator.io", "My app")
        .unwrap()
        .follow_redirects_write(&mut File::create("example.html").unwrap())
        .unwrap()
}
