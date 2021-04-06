# Changelog
All notable changes to this project will be documented in this file.

## Unreleased
### Fixed
- Now follows redirects to HTTPS, creating a new (with TLS) and replacing the current `Client`.

## 0.4.1 - 2002-11-27
### Removed
- Old response system

### Changed
- Updated README example

## 0.4.0 - 2020-11-16
### Changed
- Completely rewrote request system.
- Now tries to read instead of using threads.

### Fixed
- A bug where redirects messed up the system

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
