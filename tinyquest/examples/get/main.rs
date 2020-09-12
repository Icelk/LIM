fn main() {
  match tinyquest::get("google.com", "TINYQUEST") {
    Err(err) => eprintln!("Failed: {:?}", err),
    Ok(result) => {
      match result.get() {
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
