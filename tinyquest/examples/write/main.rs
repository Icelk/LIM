use std::fs::File;

fn main() {
    let request = http::Request::get("alligator.io").body(Vec::new()).unwrap();
    tinyquest::request(request, tinyquest::Config::no_header())
        .unwrap()
        .follow_redirects_write(&mut File::create("example.html").unwrap())
        .unwrap()
}
