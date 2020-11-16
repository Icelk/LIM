fn main() {
    match tinyquest::get("http://google.com:80/", "TINYQUEST") {
        Err(err) => eprintln!("Failed: {:?}", err),
        Ok(mut result) => {
            match result.follow_redirects() {
                Ok(s) => {
                    let (parts, body) = s.into_parts();
                    println!(
                        "Headers: '{:#?}'\n\
                        Body: '{}'",
                        parts.headers,
                        String::from_utf8_lossy(&body),
                    );
                }
                Err(err) => eprintln!("Failed: {:#?}", err),
            };
        }
    };
}
