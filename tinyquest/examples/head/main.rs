fn main() {
  match tinyquest::request_blocking(
    http::Request::head("https://icelk.dev/capturing/hi!")
      .body(Vec::new())
      .expect("Failed to build request."),
    tinyquest::Config::default(),
  ) {
    Ok(response) => {
      let (parts, body) = response.into_parts();
      println!(
        "Headers: '{:#?}'\n\
        Body: '{}'",
        parts.headers,
        String::from_utf8_lossy(&body),
      );
    }
    Err(err) => {
      panic!("An error occurred! {:?}", err);
    }
  }
}
