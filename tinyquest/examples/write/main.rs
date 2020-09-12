use std::fs::File;

fn main() {
  tinyquest::write(
    "alligator.io",
    "My app",
    Box::new(File::create("example.html").unwrap()),
  )
  .unwrap()
  .get()
  .unwrap()
}
