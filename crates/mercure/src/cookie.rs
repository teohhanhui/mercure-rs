/// [The Mercure Protocol, Section 6](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-6)
///
/// > If the publisher or the subscriber is a web browser, it SHOULD send a
/// > cookie called "mercureAuthorization" containing the JWS when connecting to
/// > the hub.
pub const MERCURE_AUTHORIZATION_COOKIE_NAME: &str = "mercureAuthorization";

/// [RFC 6265bis, Section 5.5](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.5)
pub const MAX_AGE_LIMIT: std::time::Duration = std::time::Duration::from_secs(34_560_000);
