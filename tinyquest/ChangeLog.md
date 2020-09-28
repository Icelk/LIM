# Changelog
All notable changes to this project will be documented in this file.

## 0.3.0 - 2020-09-28
### Fixed
- Now ports are supported, not only using 443

### Added
- A blocking client to remove the overhead of spawning a new system-thread
- Ability to communicate over non-encrypted connections when handshake fails

## 0.2.0 - 2020-09-25
### Fixed
- Chunked encoding is now properly decoded

## 0.1.0 - 2020-09-12
### Added
- Initial release
- Basic functionality to make HTTP requests with the OS's built in SSL service
