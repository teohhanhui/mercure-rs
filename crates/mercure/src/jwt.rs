use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use biscuit::jwa::SignatureAlgorithm;
use biscuit::{jws, ClaimsSet, RegisteredClaims, JWT};
use secrecy::{ExposeSecret as _, SecretSlice};
use serde::{Deserialize, Serialize};

use crate::topic_selector::TopicSelector;

/// [RFC 7518, Section 3.2](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
///
/// > A key of the same size as the hash output (for instance, 256 bits for
/// > "HS256") or larger MUST be used with this algorithm. (This requirement is
/// > based on Section 5.3.4 (Security Effect of the HMAC Key) of NIST SP
/// > 800-117 [[NIST.800-107]], which states that the effective security
/// > strength is the minimum of the security strength of the key and two times
/// > the size of the internal hash value.)
///
/// [NIST.800-107]: http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf
pub const HS256_SECRET_KEY_LEN: usize = 64;

/// A publisher [JWT] access token.
///
/// [JWT]: https://datatracker.ietf.org/doc/html/rfc7519
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PublisherJwt(JWT<MercureJwtClaims, biscuit::Empty>);

/// The [HMAC] secret key used to sign publisher [JWT] access tokens.
///
/// [HMAC]: https://datatracker.ietf.org/doc/html/rfc2104
/// [JWT]: https://datatracker.ietf.org/doc/html/rfc7519
///
/// # Note
///
/// It is recommended to use a key with a minimum length of
/// [`HS256_SECRET_KEY_LEN`] bytes.
///
/// [RFC 7518, Section 3.2](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
///
/// > A key of the same size as the hash output (for instance, 256 bits for
/// > "HS256") or larger MUST be used with this algorithm. (This requirement is
/// > based on Section 5.3.4 (Security Effect of the HMAC Key) of NIST SP
/// > 800-117 [[NIST.800-107]], which states that the effective security
/// > strength is the minimum of the security strength of the key and two times
/// > the size of the internal hash value.)
///
/// [NIST.800-107]: http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf
#[derive(Clone)]
pub struct PublisherJwtSecret(SecretSlice<u8>);

/// An error returned from [`PublisherJwt::new`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PublisherJwtError {
    kind: PublisherJwtErrorKind,
    inner: Box<dyn Error + Send + Sync + 'static>,
}

/// The various types of errors that can cause [`PublisherJwt::new`] to fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublisherJwtErrorKind {
    /// Failed to encode and sign publisher JWT.
    EncodeAndSign,
}

/// A subscriber [JWT] access token.
///
/// [JWT]: https://datatracker.ietf.org/doc/html/rfc7519
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SubscriberJwt(JWT<MercureJwtClaims, biscuit::Empty>);

/// The [HMAC] secret key used to sign subscriber [JWT] access tokens.
///
/// [HMAC]: https://datatracker.ietf.org/doc/html/rfc2104
/// [JWT]: https://datatracker.ietf.org/doc/html/rfc7519
///
/// # Note
///
/// It is recommended to use a key with a minimum length of
/// [`HS256_SECRET_KEY_LEN`] bytes.
///
/// [RFC 7518, Section 3.2](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
///
/// > A key of the same size as the hash output (for instance, 256 bits for
/// > "HS256") or larger MUST be used with this algorithm. (This requirement is
/// > based on Section 5.3.4 (Security Effect of the HMAC Key) of NIST SP
/// > 800-117 [[NIST.800-107]], which states that the effective security
/// > strength is the minimum of the security strength of the key and two times
/// > the size of the internal hash value.)
///
/// [NIST.800-107]: http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf
#[derive(Clone)]
pub struct SubscriberJwtSecret(SecretSlice<u8>);

/// The max-age used to calculate and set the "exp"[^exp] claim in the
/// subscriber [JWT] access token.
///
/// [JWT]: https://datatracker.ietf.org/doc/html/rfc7519
///
/// [^exp]: <https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4>
#[derive(Copy, Clone, Debug)]
pub struct SubscriberJwtMaxAge(std::time::Duration);

/// The error type returned when a conversion from [`std::time::Duration`] to
/// [`SubscriberJwtMaxAge`] fails.
#[derive(Debug)]
#[non_exhaustive]
pub struct TryFromDurationError {
    kind: TryFromDurationErrorKind,
}

/// The various types of errors that can cause converting from
/// [`std::time::Duration`] to [`SubscriberJwtMaxAge`] to fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum TryFromDurationErrorKind {
    /// Subscriber JWT max-age must not be more than [`MAX_AGE_LIMIT`].
    ///
    /// [`MAX_AGE_LIMIT`]: crate::cookie::MAX_AGE_LIMIT
    CookieLifetimeLimitExceeded,
}

/// An error returned from [`SubscriberJwt::new`].
#[derive(Debug)]
#[non_exhaustive]
pub struct SubscriberJwtError {
    kind: SubscriberJwtErrorKind,
    inner: Box<dyn Error + Send + Sync + 'static>,
}

/// The various types of errors that can cause [`SubscriberJwt::new`] to fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum SubscriberJwtErrorKind {
    /// Failed to encode and sign subscriber JWT.
    EncodeAndSign,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct MercureJwtClaims {
    mercure: MercureClaim,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct MercureClaim {
    /// [The Mercure Protocol, Section 6.1](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-6.1)
    ///
    /// > To be allowed to publish an update, the JWS presented by the publisher
    /// > MUST contain a claim called "mercure", and this claim MUST contain a
    /// > "publish" key. "mercure.publish" contains an array of topic selectors.
    #[serde(skip_serializing_if = "Option::is_none")]
    publish: Option<Vec<TopicSelector>>,
    /// [The Mercure Protocol, Section 6.2](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-6.2)
    ///
    /// > To receive updates marked as "private", the JWS presented by the
    /// > subscriber MUST have a claim named "mercure" with a key named
    /// > "subscribe" that contains an array of topic selectors.
    #[serde(skip_serializing_if = "Option::is_none")]
    subscribe: Option<Vec<TopicSelector>>,
}

impl fmt::Display for PublisherJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let jwt = self
            .0
            .encoded()
            .expect("`PublisherJwt` should be already encoded");
        write!(f, "{jwt}")
    }
}

impl PublisherJwt {
    /// Constructs a new `PublisherJwt`.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::error::Error;
    /// #
    /// use mercure::jwt::PublisherJwtSecret;
    /// use mercure::{PublisherJwt, TopicSelector};
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let publisher_jwt_secret =
    ///     PublisherJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
    /// let publisher_jwt = PublisherJwt::new(&publisher_jwt_secret, vec![TopicSelector::Wildcard])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        publisher_jwt_secret: &PublisherJwtSecret,
        topic_selectors: Vec<TopicSelector>,
    ) -> Result<Self, PublisherJwtError> {
        let mercure_jwt = JWT::<MercureJwtClaims, biscuit::Empty>::new_decoded(
            jws::RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                ..Default::default()
            }
            .into(),
            ClaimsSet {
                registered: RegisteredClaims::default(),
                private: MercureJwtClaims {
                    mercure: MercureClaim {
                        publish: Some(topic_selectors),
                        subscribe: None,
                    },
                },
            },
        );
        let mercure_jwt = match mercure_jwt.encode(&jws::Secret::Bytes(
            publisher_jwt_secret.0.expose_secret().to_vec(),
        )) {
            Ok(mercure_jwt) => mercure_jwt,
            Err(biscuit::errors::Error::UnsupportedOperation) => {
                panic!("`mercure_jwt` should not already be encoded");
            },
            Err(err) => {
                return Err(PublisherJwtError {
                    kind: PublisherJwtErrorKind::EncodeAndSign,
                    inner: err.into(),
                })?;
            },
        };

        Ok(Self(mercure_jwt))
    }
}

impl From<Vec<u8>> for PublisherJwtSecret {
    fn from(vec: Vec<u8>) -> Self {
        Self(SecretSlice::from(vec))
    }
}

impl fmt::Display for PublisherJwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PublisherJwtErrorKind::EncodeAndSign => {
                let err = self.inner.downcast_ref::<biscuit::errors::Error>().unwrap();
                write!(f, "failed to encode and sign JWT: {err}")
            },
        }
    }
}

impl Error for PublisherJwtError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            PublisherJwtErrorKind::EncodeAndSign => {
                let err = self.inner.downcast_ref::<biscuit::errors::Error>().unwrap();
                Some(err)
            },
        }
    }
}

impl PublisherJwtError {
    /// Returns the corresponding [`PublisherJwtErrorKind`] for this error.
    #[must_use]
    pub const fn kind(&self) -> &PublisherJwtErrorKind {
        &self.kind
    }
}

impl fmt::Display for SubscriberJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let jwt = self
            .0
            .encoded()
            .expect("`SubscriberJwt` should be already encoded");
        write!(f, "{jwt}")
    }
}

impl SubscriberJwt {
    /// Creates a new `SubscriberJwt`.
    ///
    /// # Note
    ///
    /// It is recommended to provide a [`SubscriberJwtMaxAge`].
    ///
    /// [The Mercure Protocol, Section 6](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-6)
    ///
    /// > This JWS SHOULD be short-lived, especially if the subscriber is a web
    /// > browser.
    ///
    /// [The Mercure Protocol, Section 12](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-12)
    ///
    /// > revoking JWSs before their expiration is often difficult. To that end,
    /// > using short-lived tokens is strongly RECOMMENDED.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::error::Error;
    /// #
    /// use mercure::jwt::SubscriberJwtSecret;
    /// use mercure::{SubscriberJwt, TopicSelector};
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let subscriber_jwt_secret =
    ///     SubscriberJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
    /// let subscriber_jwt = SubscriberJwt::new(&subscriber_jwt_secret, None, vec![
    ///     TopicSelector::UriTemplate("https://example.com/users/1/books/{book_id}".try_into()?),
    /// ])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        subscriber_jwt_secret: &SubscriberJwtSecret,
        subscriber_jwt_max_age: Option<SubscriberJwtMaxAge>,
        topic_selectors: Vec<TopicSelector>,
    ) -> Result<Self, SubscriberJwtError> {
        let mercure_jwt = JWT::<MercureJwtClaims, biscuit::Empty>::new_decoded(
            jws::RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                ..Default::default()
            }
            .into(),
            ClaimsSet {
                registered: RegisteredClaims {
                    expiry: subscriber_jwt_max_age.map(|subscriber_jwt_max_age| {
                        let expires_at = SystemTime::now()
                            .checked_add(subscriber_jwt_max_age.0)
                            .expect("`expires_at` should fit in `SystemTime`");
                        let timestamp: i64 = expires_at
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            .try_into()
                            .expect("`timestamp` should fit in `i64`");
                        timestamp.into()
                    }),
                    ..Default::default()
                },
                private: MercureJwtClaims {
                    mercure: MercureClaim {
                        publish: None,
                        subscribe: Some(topic_selectors),
                    },
                },
            },
        );
        let mercure_jwt = match mercure_jwt.encode(&jws::Secret::Bytes(
            subscriber_jwt_secret.0.expose_secret().to_vec(),
        )) {
            Ok(mercure_jwt) => mercure_jwt,
            Err(biscuit::errors::Error::UnsupportedOperation) => {
                panic!("`mercure_jwt` should not already be encoded");
            },
            Err(err) => {
                return Err(SubscriberJwtError {
                    kind: SubscriberJwtErrorKind::EncodeAndSign,
                    inner: err.into(),
                })?;
            },
        };

        Ok(Self(mercure_jwt))
    }
}

impl From<Vec<u8>> for SubscriberJwtSecret {
    fn from(vec: Vec<u8>) -> Self {
        Self(SecretSlice::from(vec))
    }
}

impl TryFrom<std::time::Duration> for SubscriberJwtMaxAge {
    type Error = TryFromDurationError;

    fn try_from(duration: std::time::Duration) -> Result<Self, Self::Error> {
        if duration > crate::cookie::MAX_AGE_LIMIT {
            return Err(Self::Error {
                kind: TryFromDurationErrorKind::CookieLifetimeLimitExceeded,
            })?;
        }

        Ok(Self(duration))
    }
}

impl From<SubscriberJwtMaxAge> for std::time::Duration {
    fn from(subscriber_jwt_max_age: SubscriberJwtMaxAge) -> Self {
        subscriber_jwt_max_age.0
    }
}

impl SubscriberJwtMaxAge {
    pub const MAX: Self = Self(crate::cookie::MAX_AGE_LIMIT);
}

impl fmt::Display for TryFromDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TryFromDurationErrorKind::CookieLifetimeLimitExceeded => {
                const SECONDS_IN_DAYS: u64 = 60 * 60 * 24;
                const LIMIT_DAYS: u64 = crate::cookie::MAX_AGE_LIMIT.as_secs() / SECONDS_IN_DAYS;
                write!(f, "max-age must not be more than {LIMIT_DAYS} days")
            },
        }
    }
}

impl Error for TryFromDurationError {}

impl TryFromDurationError {
    /// Returns the corresponding [`TryFromDurationErrorKind`] for this error.
    #[must_use]
    pub const fn kind(&self) -> &TryFromDurationErrorKind {
        &self.kind
    }
}

impl fmt::Display for SubscriberJwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            SubscriberJwtErrorKind::EncodeAndSign => {
                let err = self.inner.downcast_ref::<biscuit::errors::Error>().unwrap();
                write!(f, "failed to encode and sign JWT: {err}")
            },
        }
    }
}

impl Error for SubscriberJwtError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            SubscriberJwtErrorKind::EncodeAndSign => {
                let err = self.inner.downcast_ref::<biscuit::errors::Error>().unwrap();
                Some(err)
            },
        }
    }
}

impl SubscriberJwtError {
    /// Returns the corresponding [`SubscriberJwtErrorKind`] for this error.
    #[must_use]
    pub const fn kind(&self) -> &SubscriberJwtErrorKind {
        &self.kind
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context as _, Result};

    use super::*;

    #[test]
    fn it_creates_publisher_jwt_with_wildcard() -> Result<()> {
        let publisher_jwt_secret =
            PublisherJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
        let publisher_jwt =
            PublisherJwt::new(&publisher_jwt_secret, vec![TopicSelector::Wildcard])?;
        let publisher_jwt = publisher_jwt.0.encoded().context("JWT is not encoded")?;
        assert_eq!(
            publisher_jwt.to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXJjdXJlIjp7InB1Ymxpc2giOlsiKiJdfX0.\
             a8cjcSRUAcHdnGNMKifA4BK5epRXxQI0UBp2XpNrBdw"
        );
        Ok(())
    }

    #[test]
    fn it_creates_publisher_jwt_with_uri_template() -> Result<()> {
        let publisher_jwt_secret =
            PublisherJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
        let publisher_jwt =
            PublisherJwt::new(&publisher_jwt_secret, vec![TopicSelector::UriTemplate(
                "https://example.com/books/{book_id}".try_into()?,
            )])?;
        let publisher_jwt = publisher_jwt.0.encoded().context("JWT is not encoded")?;
        assert_eq!(
            publisher_jwt.to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJtZXJjdXJlIjp7InB1Ymxpc2giOlsiaHR0cHM6Ly9leGFtcGxlLmNvbS9ib29rcy97Ym9va19pZH0iXX19.\
             eyl-c2BUWrnx6VZNBfKWnTI2t28yO5NcHUgn83womNE"
        );
        Ok(())
    }

    #[test]
    fn it_creates_subscriber_jwt_with_wildcard() -> Result<()> {
        let subscriber_jwt_secret =
            SubscriberJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
        let subscriber_jwt =
            SubscriberJwt::new(&subscriber_jwt_secret, None, vec![TopicSelector::Wildcard])?;
        let subscriber_jwt = subscriber_jwt.0.encoded().context("JWT is not encoded")?;
        assert_eq!(
            subscriber_jwt.to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXJjdXJlIjp7InN1YnNjcmliZSI6WyIqIl19fQ.\
             TMzyyYqIldgBLhqpiOR9a_HBk7iiP60Pb4X65ICaouA"
        );
        Ok(())
    }

    #[test]
    fn it_creates_subscriber_jwt_with_uri_template() -> Result<()> {
        let subscriber_jwt_secret =
            SubscriberJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
        let subscriber_jwt = SubscriberJwt::new(&subscriber_jwt_secret, None, vec![
            TopicSelector::UriTemplate("https://example.com/users/1/books/{book_id}".try_into()?),
        ])?;
        let subscriber_jwt = subscriber_jwt.0.encoded().context("JWT is not encoded")?;
        assert_eq!(
            subscriber_jwt.to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJtZXJjdXJlIjp7InN1YnNjcmliZSI6WyJodHRwczovL2V4YW1wbGUuY29tL3VzZXJzLzEvYm9va3Mve2Jvb2tfaWR9Il19fQ.\
             8ctfXioRle93VxIwoCxikZtTBBSGrL_WtkXrS5wVPDY"
        );
        Ok(())
    }
}
