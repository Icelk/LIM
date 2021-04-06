#![warn(missing_debug_implementations)]

use bytes::Bytes;
use chunked_transfer::Decoder;
use http::{Request, Version};
use native_tls::TlsConnector;
use std::io::{self, prelude::*};
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Debug)]
pub enum Error {
    FailedToConnect,
    FailedToHandshake,
    FailedToWrite,
    StreamBroken,
    /// If the client had to make a new request due to the redirect policy.
    WouldBlock,

    IO(io::Error),
    Request(RequestError),
    Response(ResponseError),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock => Error::WouldBlock,
            _ => Error::IO(error),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
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

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum Content {
    Body,
    Header,
    Both,
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Config {
    redirect_policy: RedirectPolicy,
    header: Content,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            redirect_policy: RedirectPolicy::default(),
            header: Content::Both,
        }
    }
}
impl Config {
    pub fn no_header() -> Self {
        Config {
            redirect_policy: RedirectPolicy::default(),
            header: Content::Body,
        }
    }
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
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

#[derive(Debug)]
enum Connector {
    Raw(TcpStream),
    TLS(native_tls::TlsStream<TcpStream>),
}
impl Connector {
    pub fn set_read_timeout(
        &mut self,
        dur: std::option::Option<std::time::Duration>,
    ) -> io::Result<()> {
        match self {
            Self::Raw(stream) => stream.set_read_timeout(dur),
            Self::TLS(tls_stream) => tls_stream.get_mut().set_read_timeout(dur),
        }
    }
}
impl Write for Connector {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Raw(stream) => stream.write(buf),
            Self::TLS(tls_stream) => tls_stream.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Raw(stream) => stream.flush(),
            Self::TLS(tls_stream) => tls_stream.flush(),
        }
    }
}
impl Read for Connector {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(stream) => stream.read(buf),
            Self::TLS(tls_stream) => tls_stream.read(buf),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    stream: Connector,
    config: Arc<Config>,
    request: Option<http::Request<Vec<u8>>>,
    redirects: u32,
}
impl Client {
    pub fn connect(config: Arc<Config>, host: &str, port: u16, use_https: bool) -> Result<Self> {
        let tcp_stream = match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(stream) => stream,
            Err(err) => {
                return Err(Error::IO(err));
            }
        };

        let stream = if use_https {
            let connector = match TlsConnector::new() {
                Ok(conn) => conn,
                Err(..) => {
                    return Err(Error::FailedToConnect);
                }
            };
            Connector::TLS(match connector.connect(host, tcp_stream) {
                Ok(stream) => stream,
                Err(..) => {
                    return Err(Error::FailedToHandshake);
                }
            })
        } else {
            Connector::Raw(tcp_stream)
        };
        Ok(Self {
            config,
            stream,
            request: None,
            redirects: 0,
        })
    }
    pub fn request(&mut self, request: Request<Vec<u8>>) -> Result<()> {
        self.request = Some(request);
        self._request()
    }
    /// # Panics
    /// This function will panic if the internal `request` parameter is None.
    fn _request(&mut self) -> Result<()> {
        let request = self.request.as_ref().unwrap();
        let uri = match request.uri().path() {
            uri if !uri.is_empty() => uri,
            _ => "/",
        };
        let domain = match request.uri().host() {
            Some(dom) => dom,
            None => {
                return Err(Error::Request(RequestError::NoHost));
            }
        };
        let method = request.method().as_str();
        let version = match request.version() {
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
                Connection: keep-alive\r\n\
                Accept-Encoding: identity\r\n",
                method, uri, version, domain,
            )
            .as_bytes(),
        );
        // Add headers
        for (name, value) in request.headers().iter() {
            http_req.extend(name.as_str().as_bytes());
            http_req.extend(b": ");
            http_req.extend(value.as_bytes());
            http_req.extend(LINE_ENDING);
        }
        http_req.extend(LINE_ENDING);

        match self
            .stream
            .write_all(&http_req[..])
            .and(self.stream.flush())
        {
            Ok(()) => (),
            Err(err) => {
                return Err(Error::IO(err));
            }
        };
        // Not optimal; make it smart and read chunked encoding later!
        self.stream
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
        Ok(())
    }
    fn _handle(&mut self) -> Result<(Vec<u8>, usize, Vec<u8>, u16, http::HeaderMap)> {
        let mut bytes = Self::read_to_vec(&mut self.stream)?;

        let mut version = Vec::new();
        let mut status_code = Vec::new();
        let mut reason_phrase = Vec::new();
        let mut headers = http::HeaderMap::with_capacity(32);
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
                                return Err(Error::Response(ResponseError::InvalidHeaderName));
                            }
                        },
                        match http::header::HeaderValue::from_bytes(&value) {
                            Ok(value) => value,
                            Err(..) => {
                                return Err(Error::Response(ResponseError::InvalidHeaderValue));
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

        if headers
            .get("transfer-encoding")
            .and_then(|header| header.to_str().ok())
            .map(|string| string.to_ascii_lowercase() == "chunked")
            .unwrap_or(false)
        {
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
                    return Err(Error::Response(ResponseError::InvalidStatusCode));
                }
                Ok(parsed) => parsed,
            },
            Err(..) => {
                return Err(Error::Response(ResponseError::InvalidHeaderUtf8));
            }
        };

        if status >= 300
            && status < 400
            && status != 305
            && headers.contains_key("location")
            && (match self.config.redirect_policy {
                RedirectPolicy::Stay => false,
                RedirectPolicy::Max(redirects) => self.redirects < redirects,
                RedirectPolicy::Continue => true,
            })
        {
            self.redirects += 1;
            let mutable_uri = match &mut self.request {
                Some(request) => request.uri_mut(),
                None => unreachable!(),
            };
            *mutable_uri = match headers.get("location") {
                Some(location) => {
                    match http::Uri::from_maybe_shared(Bytes::copy_from_slice(location.as_bytes()))
                    {
                    Ok(location) => location,
                    Err(..) => {
                        return Err(Error::Response(ResponseError::RedirectBrokenLocation));
                    }
                    }
                }
                None => {
                    return Err(Error::Response(ResponseError::RedirectMissingLocation));
                }
            };
            self._request()?;
            return Err(Error::WouldBlock);
        }
        Ok((bytes, last_byte, version, status, headers))
    }

    pub(crate) fn read_to_vec(reader: &mut dyn Read) -> Result<Vec<u8>> {
        const BYTES_ADD: usize = 8 * 1024;

        let mut bytes = Vec::with_capacity(BYTES_ADD);
        unsafe { bytes.set_len(BYTES_ADD) };
        let mut began_recieving = false;
        let mut read = 0;
        loop {
            match reader.read(&mut bytes[read..]) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    std::thread::yield_now();
                    continue;
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut =>
                {
                    if began_recieving {
                        break;
                    } else {
                        std::thread::yield_now();
                        continue;
                    }
                }

                Err(err) => {
                    return Err(Error::IO(err));
                }
                Ok(just_read) => {
                    began_recieving = true;
                    read += just_read;

                    if read == bytes.len() {
                        bytes.reserve(BYTES_ADD);
                        unsafe { bytes.set_len(bytes.capacity()) };
                    }
                }
            };
        }
        unsafe { bytes.set_len(read) };
        Ok(bytes)
    }

    pub fn done(&mut self) -> bool {
        let result = self.stream.read(&mut [0; 0]).is_ok();
        result
    }
    pub fn wait(&mut self) -> Result<http::Response<Vec<u8>>> {
        let mut response = http::Response::builder();
        let (bytes, last_byte, version, status, headers) = self._handle()?;
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

        for (name, value) in headers.iter() {
            response = response.header(name, value);
        }

        let mut body: Vec<u8> = bytes.into_iter().skip(last_byte).collect();
        body.truncate(body.len());

        match response.body(body) {
            Ok(res) => Ok(res),
            Err(..) => Err(Error::Response(ResponseError::FailedToConstructResponse)),
        }
    }
    pub fn follow_redirects(&mut self) -> Result<http::Response<Vec<u8>>> {
        loop {
            match self.wait() {
                Err(Error::WouldBlock) => continue,
                Err(err) => return Err(err),
                Ok(result) => return Ok(result),
            }
        }
    }
    pub fn write(&mut self, writer: &mut dyn Write) -> Result<()> {
        let (bytes, last_byte, _, _, _) = self._handle()?;

        let start_at = match self.config.header {
            Content::Body => last_byte,
            _ => 0,
        };
        let end_at = match self.config.header {
            Content::Header => last_byte,
            _ => bytes.len(),
        };

        writer
            .write_all(&bytes[start_at..end_at])
            .map_err(|err| err.into())
    }
    pub fn follow_redirects_write(&mut self, writer: &mut dyn Write) -> Result<()> {
        loop {
            match self.write(writer) {
                Err(Error::WouldBlock) => continue,
                Err(err) => return Err(err),
                Ok(result) => return Ok(result),
            }
        }
    }
}

const LINE_ENDING: &[u8] = b"\r\n";

pub fn get(url: &str, user_agent: &str) -> Result<Client> {
    let req = match Request::get(url)
        .header("User-Agent", user_agent)
        .body(Vec::new())
    {
        Ok(req) => req,
        Err(err) => return Err(Error::Request(RequestError::FailedToConstructRequest(err))),
    };
    let host = match req.uri().host() {
        Some(host) => host,
        None => return Err(Error::Request(RequestError::NoHost)),
    };
    let port = req.uri().port_u16().unwrap_or(443);
    let mut result = Client::connect(Arc::new(Config::default()), host, port, port == 443)?;
    result.request(req)?;
    Ok(result)
}
pub fn request(request: http::Request<Vec<u8>>, config: Config) -> Result<Client> {
    let host = match request.uri().host() {
        Some(host) => host,
        None => return Err(Error::Request(RequestError::NoHost)),
    };
    let port = request.uri().port_u16().unwrap_or(443);
    let mut result = Client::connect(Arc::new(config), host, port, port == 443)?;
    result.request(request)?;
    Ok(result)
}
