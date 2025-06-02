# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-06-03

### Added

- **\[BREAKING\]** `impl TryFrom<Url> for HubUrl` which validates the path of
  the URL.
- Examples in documentation.

### Changed

- **\[BREAKING\]** Rename `MercureHubUrl` to `HubUrl`.
- **\[BREAKING\]** Change `PublishUpdatePrivacy::is_public` to private.
- Update documentation.

### Removed

- **\[BREAKING\]** Re-exports at crate root:
    - `PublisherJwtSecret`
    - `SubscriberJwtMaxAge`
    - `SubscriberJwtSecret`
- **\[BREAKING\]** `MercureHubUrl::new`
- **\[BREAKING\]** `PublishUpdatePrivacy::is_private`

## [0.1.0] - 2025-06-01

- Initial release.

[Unreleased]: https://github.com/teohhanhui/mercure-rs/compare/v0.1.0...HEAD
[0.2.0]: https://github.com/teohhanhui/mercure-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/teohhanhui/mercure-rs/releases/tag/v0.1.0
