use chunked_transfer::Decoder;
use core::convert::TryFrom;
use http::{Request, Version};
#[cfg(not(feature = "support"))]
use native_tls::TlsConnector;
use std::io::{self, prelude::*};
use std::iter::FromIterator;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{mem, thread};
#[cfg(feature = "support")]
use {rustls, webpki, webpki_roots};

#[derive(Debug)]
pub enum Error {
  FailedToConnect,
  FailedToHandshake,
  FailedToWrite,
  StreamBroken,
  NotReady,

  IO(io::Error),
  Request(RequestError),
  Response(ResponseError),
}
#[derive(Debug)]
pub enum RequestError {
  FailedToGetIP,
  NoHost,
  FailedToConstructRequest(http::Error),
  FailedToSetNoDelay,
}
#[derive(Debug)]
pub enum ResponseError {
  InvalidHeaderName,
  InvalidHeaderValue,
  InvalidHeaderUtf8,
  InvalidStatusCode,
  FailedToConstructResponse,
  RedirectMissingLocation,
  RedirectBrokenLocation,
}

pub struct Response<T> {
  data: Arc<Mutex<Result<T, Error>>>,
}
impl<T> Response<http::Response<T>>
where
  T: FromIterator<u8> + Default,
{
  pub fn done(&self) -> bool {
    self.data.try_lock().is_ok()
  }
  pub fn get(self) -> Result<http::Response<T>, Error> {
    let mut state = self.data.lock().expect("Failed to lock Mutex.");
    mem::replace(&mut *state, Ok(http::Response::new(T::default())))
  }
}
impl Response<()> {
  pub fn done(&self) -> bool {
    self.data.try_lock().is_ok()
  }
  pub fn get(self) -> Result<(), Error> {
    let mut state = self.data.lock().expect("Failed to lock Mutex.");
    mem::replace(&mut *state, Ok(()))
  }
}
pub enum Header {
  None,
  Only,
  Keep,
}
pub struct Config {
  redirect_policy: RedirectPolicy,
  redirects: u32,
  header: Header,
}
impl Default for Config {
  fn default() -> Self {
    Config {
      redirect_policy: RedirectPolicy::default(),
      redirects: 0,
      header: Header::Keep,
    }
  }
}
impl Config {
  pub fn no_header() -> Self {
    Config {
      redirect_policy: RedirectPolicy::default(),
      redirects: 0,
      header: Header::None,
    }
  }
}
pub enum RedirectPolicy {
  Stay,
  Max(u32),
  Continue,
}
impl Default for RedirectPolicy {
  fn default() -> Self {
    RedirectPolicy::Max(10)
  }
}

pub fn get(url: &str, user_agent: &str) -> Result<Response<http::Response<Vec<u8>>>, Error> {
  let req = match Request::get(url)
    .header("User-Agent", user_agent)
    .body(Vec::new())
  {
    Ok(req) => req,
    Err(err) => return Err(Error::Request(RequestError::FailedToConstructRequest(err))),
  };

  Ok(request(req, Config::default()))
}
pub fn request(mut req: Request<Vec<u8>>, mut config: Config) -> Response<http::Response<Vec<u8>>> {
  let output = Arc::new(Mutex::new(Err(Error::NotReady)));
  let thread_output = output.clone();
  thread::spawn(move || {
    let mut output = thread_output.lock().expect("Failed to get mutex lock.");

    let mut file = req.uri().path();
    if file.is_empty() {
      file = "/";
    }
    let domain = match req.uri().host() {
      Some(dom) => dom,
      None => {
        *output = Err(Error::Request(RequestError::NoHost));
        return;
      }
    };
    let method = req.method().as_str();
    let version = match req.version() {
      Version::HTTP_09 => "HTTP/0.9",
      Version::HTTP_10 => "HTTP/1.0",
      Version::HTTP_11 => "HTTP/1.1",
      Version::HTTP_2 => "HTTP/2.0",
      Version::HTTP_3 => "HTTP/3.0",
      _ => "HTTP/1.1",
    };
    let mut http_req = Vec::new();
    http_req.extend(
      format!(
        "{} {} {}\r\n\
      Host: {}\r\n\
      Connection: close\r\n\
      Accept-Encoding: identity\r\n",
        method, file, version, domain,
      )
      .as_bytes(),
    );

    // Add headers
    for (name, value) in req.headers().iter() {
      http_req.extend(name.as_str().as_bytes());
      http_req.extend(b": ".iter().cloned());
      http_req.extend(value.as_bytes());
      http_req.extend(b"\r\n".iter().cloned());
    }
    http_req.extend(b"\r\n".iter().cloned());

    let tcp_stream = match TcpStream::connect(format!("{}:443", domain)) {
      Ok(stream) => stream,
      Err(err) => {
        *output = Err(Error::IO(err));
        return;
      }
    };

    let mut bytes = Vec::new();
    #[cfg(feature = "support")]
    {
      let mut tcp_stream = tcp_stream;
      let mut config = rustls::ClientConfig::new();
      config.enable_early_data = true;
      config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
      let config = &Arc::new(config);
      let dns_name = match webpki::DNSNameRef::try_from_ascii_str(domain) {
        Ok(dns_name) => dns_name,
        Err(..) => {
          *output = Err(Error::Request(RequestError::FailedToGetIP));
          return;
        }
      };
      let mut sess = rustls::ClientSession::new(config, dns_name);
      match tcp_stream.set_nodelay(true) {
        Err(..) => {
          *output = Err(Error::Request(RequestError::FailedToSetNoDelay));
          return;
        }
        _ => {}
      };

      // If early data is available with this server, then early_data()
      // will yield Some(WriteEarlyData) and WriteEarlyData implements
      // io::Write.  Use this to send the request.
      if let Some(mut early_data) = sess.early_data() {
        match early_data.write(&http_req[..]) {
          Err(err) => {
            *output = Err(Error::IO(err));
            return;
          }
          _ => {}
        };
      }
      let mut stream = rustls::Stream::new(&mut sess, &mut tcp_stream);

      // Complete handshake.
      match stream.flush() {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };

      // If we didn't send early data, or the server didn't accept it,
      // then send the request as normal.
      if !stream.sess.is_early_data_accepted() {
        match stream.write_all(&http_req[..]) {
          Err(err) => {
            *output = Err(Error::IO(err));
            return;
          }
          _ => {}
        };
      }
      match stream.read_to_end(&mut bytes) {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };
    }
    #[cfg(not(feature = "support"))]
    {
      let connector = match TlsConnector::new() {
        Ok(conn) => conn,
        Err(..) => {
          *output = Err(Error::FailedToConnect);
          return;
        }
      };
      let mut stream = match connector.connect(domain, tcp_stream) {
        Ok(stream) => stream,
        Err(..) => {
          *output = Err(Error::FailedToHandshake);
          return;
        }
      };

      match stream.write_all(&http_req[..]) {
        Ok(()) => (),
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
      };
      match stream.read_to_end(&mut bytes) {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };
    }

    let mut response = http::Response::builder();
    let mut version = Vec::new();
    let mut status_code = Vec::new();
    let mut reason_phrase = Vec::new();
    let headers = response.headers_mut().expect("Failed to get headers!");
    let mut key = Vec::new();
    let mut value = Vec::new();

    let mut segment = 0;
    let mut newlines = 0;

    let mut last_byte = 0;

    // Parse header
    for byte in bytes.iter() {
      last_byte += 1;
      if *byte == 32 {
        // Space
        if segment != -1 {
          segment += 1;
          continue;
        }
      }
      if *byte == 10 {
        // Line Feed
        newlines += 1;
        segment = -2;
        if !key.is_empty() || !value.is_empty() {
          headers.insert(
            match http::header::HeaderName::from_bytes(&key) {
              Ok(name) => name,
              Err(..) => {
                *output = Err(Error::Response(ResponseError::InvalidHeaderName));
                return;
              }
            },
            match http::header::HeaderValue::from_bytes(&value) {
              Ok(value) => value,
              Err(..) => {
                *output = Err(Error::Response(ResponseError::InvalidHeaderValue));
                return;
              }
            },
          );
          key.clear();
          value.clear();
        }
        // If double newline, it's body-time!
        if newlines == 2 {
          break;
        }
        continue;
      } else if *byte != 13 {
        newlines = 0;
      }
      // Filter out CR and colon
      if *byte == 13 || (*byte == 58 && segment != -1) {
        continue;
      }

      match segment {
        0 => version.push(*byte),
        1 => status_code.push(*byte),
        2 => reason_phrase.push(*byte),
        -2 => key.push(*byte),
        -1 => value.push(*byte),
        _ => {}
      };
    }

    if headers.get("transfer-encoding") == Some(&"chunked".parse().unwrap()) {
      let mut buffer = Vec::with_capacity(bytes.len());
      buffer.extend(&bytes[..last_byte]);
      let mut decoder = Decoder::new(&bytes[last_byte..]);
      if let Ok(..) = decoder.read_to_end(&mut buffer) {
        bytes = buffer;
      }
    }

    let status = match String::from_utf8(status_code) {
      Ok(s) => match s.parse::<u16>() {
        Err(..) => {
          *output = Err(Error::Response(ResponseError::InvalidStatusCode));
          return;
        }
        Ok(parsed) => parsed,
      },
      Err(..) => {
        *output = Err(Error::Response(ResponseError::InvalidHeaderUtf8));
        return;
      }
    };

    if status >= 300
      && status < 400
      && status != 305
      && headers.contains_key("location")
      && (match config.redirect_policy {
        RedirectPolicy::Stay => false,
        RedirectPolicy::Max(redirects) => config.redirects < redirects,
        RedirectPolicy::Continue => true,
      })
    {
      config.redirects += 1;
      *req.uri_mut() = match headers.get("location") {
        Some(location) => match http::Uri::try_from(match location.to_str() {
          Ok(location) => location,
          Err(..) => {
            *output = Err(Error::Response(ResponseError::RedirectBrokenLocation));
            return;
          }
        }) {
          Ok(location) => location,
          Err(..) => {
            *output = Err(Error::Response(ResponseError::RedirectBrokenLocation));
            return;
          }
        },
        None => {
          *output = Err(Error::Response(ResponseError::RedirectMissingLocation));
          return;
        }
      };
      *output = request(req, config).get();
      return;
    }

    response = response
      .version(match &version[..] {
        b"HTTP/0.9" => Version::HTTP_09,
        b"HTTP/1.0" => Version::HTTP_10,
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/2.0" => Version::HTTP_2,
        b"HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
      })
      .status(status);

    let mut body: Vec<u8> = bytes.into_iter().skip(last_byte).collect();
    body.truncate(body.len());

    *output = Ok(match response.body(body) {
      Ok(res) => res,
      Err(..) => {
        *output = Err(Error::Response(ResponseError::FailedToConstructResponse));
        return;
      }
    });
  });

  while output.try_lock().is_ok() {}

  Response { data: output }
}

pub fn write(
  url: &str,
  user_agent: &str,
  writer: Box<dyn Write + Send>,
) -> Result<Response<()>, Error> {
  let req = match Request::get(url)
    .header("User-Agent", user_agent)
    .body(Vec::new())
  {
    Ok(req) => req,
    Err(err) => return Err(Error::Request(RequestError::FailedToConstructRequest(err))),
  };

  Ok(request_write(req, Config::no_header(), writer))
}
pub fn request_write(
  mut req: Request<Vec<u8>>,
  mut config: Config,
  mut writer: Box<dyn Write + Send>,
) -> Response<()> {
  let output: Arc<Mutex<Result<(), Error>>> = Arc::new(Mutex::new(Err(Error::NotReady)));
  let thread_output = output.clone();
  thread::spawn(move || {
    let mut output = thread_output.lock().expect("Failed to get mutex lock.");

    let mut file = req.uri().path();
    if file.is_empty() {
      file = "/";
    }
    let domain = match req.uri().host() {
      Some(dom) => dom,
      None => {
        *output = Err(Error::Request(RequestError::NoHost));
        return;
      }
    };
    let method = req.method().as_str();
    let version = match req.version() {
      Version::HTTP_09 => "HTTP/0.9",
      Version::HTTP_10 => "HTTP/1.0",
      Version::HTTP_11 => "HTTP/1.1",
      Version::HTTP_2 => "HTTP/2.0",
      Version::HTTP_3 => "HTTP/3.0",
      _ => "HTTP/1.1",
    };
    let mut http_req = Vec::new();
    http_req.extend(
      format!(
        "{} {} {}\r\n\
      Host: {}\r\n\
      Connection: close\r\n\
      Accept-Encoding: identity\r\n",
        method, file, version, domain,
      )
      .as_bytes(),
    );

    // Add headers
    for (name, value) in req.headers().iter() {
      http_req.extend(name.as_str().as_bytes());
      http_req.extend(b": ".iter().cloned());
      http_req.extend(value.as_bytes());
      http_req.extend(b"\r\n".iter().cloned());
    }
    http_req.extend(b"\r\n".iter().cloned());

    let tcp_stream = match TcpStream::connect(format!("{}:443", domain)) {
      Ok(stream) => stream,
      Err(err) => {
        *output = Err(Error::IO(err));
        return;
      }
    };

    let mut bytes = Vec::new();
    #[cfg(feature = "support")]
    {
      let mut tcp_stream = tcp_stream;
      let mut config = rustls::ClientConfig::new();
      config.enable_early_data = true;
      config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
      let config = &Arc::new(config);
      let dns_name = match webpki::DNSNameRef::try_from_ascii_str(domain) {
        Ok(dns_name) => dns_name,
        Err(..) => {
          *output = Err(Error::Request(RequestError::FailedToGetIP));
          return;
        }
      };
      let mut sess = rustls::ClientSession::new(config, dns_name);
      match tcp_stream.set_nodelay(true) {
        Err(..) => {
          *output = Err(Error::Request(RequestError::FailedToSetNoDelay));
          return;
        }
        _ => {}
      };

      // If early data is available with this server, then early_data()
      // will yield Some(WriteEarlyData) and WriteEarlyData implements
      // io::Write.  Use this to send the request.
      if let Some(mut early_data) = sess.early_data() {
        match early_data.write(&http_req[..]) {
          Err(err) => {
            *output = Err(Error::IO(err));
            return;
          }
          _ => {}
        };
      }
      let mut stream = rustls::Stream::new(&mut sess, &mut tcp_stream);

      // Complete handshake.
      match stream.flush() {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };

      // If we didn't send early data, or the server didn't accept it,
      // then send the request as normal.
      if !stream.sess.is_early_data_accepted() {
        match stream.write_all(&http_req[..]) {
          Err(err) => {
            *output = Err(Error::IO(err));
            return;
          }
          _ => {}
        };
      }
      match stream.read_to_end(&mut bytes) {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };
    }
    #[cfg(not(feature = "support"))]
    {
      let connector = match TlsConnector::new() {
        Ok(conn) => conn,
        Err(..) => {
          *output = Err(Error::FailedToConnect);
          return;
        }
      };
      let mut stream = match connector.connect(domain, tcp_stream) {
        Ok(stream) => stream,
        Err(..) => {
          *output = Err(Error::FailedToHandshake);
          return;
        }
      };

      match stream.write_all(&http_req[..]) {
        Ok(()) => (),
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
      };
      match stream.read_to_end(&mut bytes) {
        Err(err) => {
          *output = Err(Error::IO(err));
          return;
        }
        _ => {}
      };
    }

    let mut response = http::Response::builder();
    let mut version = Vec::new();
    let mut status_code = Vec::new();
    let mut reason_phrase = Vec::new();
    let headers = response.headers_mut().expect("Failed to get headers!");
    let mut key = Vec::new();
    let mut value = Vec::new();

    let mut segment = 0;
    let mut newlines = 0;

    let mut last_byte = 0;

    // Parse header
    for byte in bytes.iter() {
      last_byte += 1;
      if *byte == 32 {
        // Space
        if segment != -1 {
          segment += 1;
          continue;
        }
      }
      if *byte == 10 {
        // Line Feed
        newlines += 1;
        segment = -2;
        if !key.is_empty() || !value.is_empty() {
          headers.insert(
            match http::header::HeaderName::from_bytes(&key) {
              Ok(name) => name,
              Err(..) => {
                *output = Err(Error::Response(ResponseError::InvalidHeaderName));
                return;
              }
            },
            match http::header::HeaderValue::from_bytes(&value) {
              Ok(value) => value,
              Err(..) => {
                *output = Err(Error::Response(ResponseError::InvalidHeaderValue));
                return;
              }
            },
          );
          key.clear();
          value.clear();
        }
        // If double newline, it's body-time!
        if newlines == 2 {
          break;
        }
        continue;
      } else if *byte != 13 {
        newlines = 0;
      }
      // Filter out CR and colon
      if *byte == 13 || (*byte == 58 && segment != -1) {
        continue;
      }

      match segment {
        0 => version.push(*byte),
        1 => status_code.push(*byte),
        2 => reason_phrase.push(*byte),
        -2 => key.push(*byte),
        -1 => value.push(*byte),
        _ => {}
      };
    }

    if headers.get("transfer-encoding") == Some(&"chunked".parse().unwrap()) {
      let mut buffer = Vec::with_capacity(bytes.len());
      buffer.extend(&bytes[..last_byte]);
      let mut decoder = Decoder::new(&bytes[last_byte..]);
      if let Ok(..) = decoder.read_to_end(&mut buffer) {
        bytes = buffer;
      }
    }

    let status = match String::from_utf8(status_code) {
      Ok(s) => match s.parse::<u16>() {
        Err(..) => {
          *output = Err(Error::Response(ResponseError::InvalidStatusCode));
          return;
        }
        Ok(parsed) => parsed,
      },
      Err(..) => {
        *output = Err(Error::Response(ResponseError::InvalidHeaderUtf8));
        return;
      }
    };

    if status >= 300
      && status < 400
      && status != 305
      && headers.contains_key("location")
      && (match config.redirect_policy {
        RedirectPolicy::Stay => false,
        RedirectPolicy::Max(redirects) => config.redirects < redirects,
        RedirectPolicy::Continue => true,
      })
    {
      config.redirects += 1;
      *req.uri_mut() = match headers.get("location") {
        Some(location) => match http::Uri::try_from(match location.to_str() {
          Ok(location) => location,
          Err(..) => {
            *output = Err(Error::Response(ResponseError::RedirectBrokenLocation));
            return;
          }
        }) {
          Ok(location) => location,
          Err(..) => {
            *output = Err(Error::Response(ResponseError::RedirectBrokenLocation));
            return;
          }
        },
        None => {
          *output = Err(Error::Response(ResponseError::RedirectMissingLocation));
          return;
        }
      };
      *output = request_write(req, config, writer).get();
      return;
    }

    let start_at = match config.header {
      Header::None => last_byte,
      _ => 0,
    };
    let end_at = match config.header {
      Header::Only => last_byte,
      _ => bytes.len(),
    };

    match writer.write_all(&mut bytes[start_at..end_at]) {
      Err(err) => {
        *output = Err(Error::IO(err));
        return;
      }
      _ => {}
    };
    *output = Ok(());
  });

  while output.try_lock().is_ok() {}

  Response { data: output }
}
