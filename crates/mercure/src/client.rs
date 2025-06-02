use std::error::Error;
use std::fmt;

use reqwest::header::{self, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::jwt::PublisherJwt;
use crate::topic::Topic;

/// [The Mercure Protocol, Section 2](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-2)
///
/// > The URL of the hub MUST be the "well-known" [[RFC5785]] fixed path
/// > "/.well-known/mercure".
///
/// [RFC5785]: https://datatracker.ietf.org/doc/html/rfc5785
const HUB_PATH: &str = "/.well-known/mercure";

/// A client for communicating with the Mercure hub.
#[derive(Clone, Debug)]
pub struct Client {
    http_client: reqwest::Client,
    hub_url: HubUrl,
    publisher_jwt: PublisherJwt,
}

/// The [URL] for connecting to the Mercure hub.
///
/// [The Mercure Protocol, Section 2](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-2)
///
/// > The URL of the hub MUST be the "well-known" [[RFC5785]] fixed path
/// > "/.well-known/mercure".
///
/// [RFC5785]: https://datatracker.ietf.org/doc/html/rfc5785
/// [URL]: https://url.spec.whatwg.org/
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct HubUrl(Url);

/// The error type returned when a conversion from [`Url`] to [`HubUrl`] fails.
#[derive(Debug)]
pub struct TryFromUrlError;

/// The privacy setting to use when publishing an update.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize)]
pub enum PublishUpdatePrivacy {
    #[serde(skip_serializing)]
    Public,
    /// [The Mercure Protocol, Section 5](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-5)
    ///
    /// > the update MUST NOT be dispatched to subscribers not authorized to
    /// > receive it.
    #[serde(rename = "on")]
    Private,
}

/// [The Mercure Protocol, Section 5](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-5)
///
/// > the topic's revision identifier: it will be used as the SSE's id property.
/// > The provided id MUST NOT start with the # character. The provided id
/// > SHOULD be a valid IRI. If omitted, the hub MUST generate a valid IRI
/// > [[RFC3987]]. An UUID [[RFC4122]] or a DID MAY be used. Alternatively the
/// > hub MAY generate a relative URI composed of a fragment (starting with #).
/// > This is convenient to return an offset or a sequence that is unique for
/// > this hub. Even if provided, the hub MAY ignore the id provided by the
/// > client and generate its own id.
///
/// [RFC3987]: https://datatracker.ietf.org/doc/html/rfc3987
/// [RFC4122]: https://datatracker.ietf.org/doc/html/rfc4122
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct RevisionId(String);

/// An error returned from [`Client::publish_update`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PublishUpdateError {
    kind: PublishUpdateErrorKind,
    inner: Box<dyn Error + Send + Sync + 'static>,
}

/// The various types of errors that can cause [`Client::publish_update`] to
/// fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublishUpdateErrorKind {
    /// Failed to serialize parameters to application/x-www-form-urlencoded.
    SerializeParameters,
    /// Failed to send publish request to Mercure hub.
    SendRequest,
    /// Failed to read publish response from Mercure hub.
    ReadResponse,
}

#[derive(Debug, Serialize)]
struct PublishUpdateParams<'a> {
    topic: Topic,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a str>,
    #[serde(rename = "private")]
    #[serde(skip_serializing_if = "PublishUpdatePrivacy::is_public")]
    privacy: PublishUpdatePrivacy,
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::error::Error;
    /// #
    /// use mercure::{HubUrl, PublisherJwt, TopicSelector};
    /// use url::Url;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let http_client = reqwest::Client::new();
    /// let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
    /// let publisher_jwt = PublisherJwt::new(
    ///     &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
    ///     vec![TopicSelector::Wildcard],
    /// )?;
    ///
    /// let client = mercure::Client::new(http_client, hub_url, publisher_jwt);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(http_client: reqwest::Client, hub_url: HubUrl, publisher_jwt: PublisherJwt) -> Self {
        Self {
            http_client,
            hub_url,
            publisher_jwt,
        }
    }

    /// Publishes an update to the Mercure hub.
    ///
    /// [The Mercure Protocol, Section 5](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-5)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// #
    /// use mercure::client::PublishUpdatePrivacy;
    /// use mercure::Topic;
    /// # use mercure::{HubUrl, PublisherJwt, TopicSelector};
    /// # use url::Url;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn Error>> {
    /// # let http_client = reqwest::Client::new();
    /// # let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
    /// # let publisher_jwt = PublisherJwt::new(
    /// #     &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
    /// #     vec![TopicSelector::Wildcard],
    /// # )?;
    /// #
    /// # let client = mercure::Client::new(http_client, hub_url, publisher_jwt);
    /// #
    /// let topic = Topic::new("https://example.com/books/1".parse()?, vec![]);
    /// let data = r#"{"isbn":"9780735218789"}"#;
    /// let privacy = PublishUpdatePrivacy::Public;
    ///
    /// client.publish_update(topic, Some(&data), privacy).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn publish_update(
        &self,
        topic: Topic,
        data: Option<&str>,
        privacy: PublishUpdatePrivacy,
    ) -> Result<RevisionId, PublishUpdateError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {jwt}", jwt = self.publisher_jwt)
                .parse()
                .expect("`publisher_jwt` should not contain invalid ASCII"),
        );

        let params = PublishUpdateParams {
            topic,
            data,
            privacy,
        };

        let res = self
            .http_client
            .post(self.hub_url.0.clone())
            .headers(headers)
            .body(
                serde_html_form::to_string(params).map_err(|err| PublishUpdateError {
                    kind: PublishUpdateErrorKind::SerializeParameters,
                    inner: err.into(),
                })?,
            )
            .send()
            .await
            .map_err(|err| PublishUpdateError {
                kind: PublishUpdateErrorKind::SendRequest,
                inner: err.into(),
            })?;

        Ok(RevisionId(res.text().await.map_err(|err| {
            PublishUpdateError {
                kind: PublishUpdateErrorKind::ReadResponse,
                inner: err.into(),
            }
        })?))
    }
}

impl TryFrom<Url> for HubUrl {
    type Error = TryFromUrlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if url.path() != HUB_PATH {
            return Err(TryFromUrlError);
        }

        Ok(Self(url))
    }
}

impl fmt::Display for HubUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{url}", url = self.0)
    }
}

impl fmt::Display for TryFromUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the path of the URL must be {HUB_PATH}")
    }
}

impl Error for TryFromUrlError {}

impl PublishUpdatePrivacy {
    /// `#[serde(skip_serializing_if = "...")]` only accepts a path.
    ///
    /// <https://github.com/serde-rs/serde/blob/v1.0.219/serde_derive/src/internals/attr.rs#L988>
    fn is_public(&self) -> bool {
        *self == Self::Public
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{rev}", rev = self.0)
    }
}

impl fmt::Display for PublishUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PublishUpdateErrorKind::SerializeParameters => {
                let err = self
                    .inner
                    .downcast_ref::<serde_html_form::ser::Error>()
                    .unwrap();
                write!(
                    f,
                    "failed to serialize parameters to application/x-www-form-urlencoded: {err}"
                )
            },
            PublishUpdateErrorKind::SendRequest => {
                let err = self.inner.downcast_ref::<reqwest::Error>().unwrap();
                write!(f, "failed to send request to Mercure hub: {err}")
            },
            PublishUpdateErrorKind::ReadResponse => {
                let err = self.inner.downcast_ref::<reqwest::Error>().unwrap();
                write!(f, "failed to read response from Mercure hub: {err}")
            },
        }
    }
}

impl Error for PublishUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.kind {
            PublishUpdateErrorKind::SerializeParameters => {
                let err = self
                    .inner
                    .downcast_ref::<serde_html_form::ser::Error>()
                    .unwrap();
                Some(err)
            },
            PublishUpdateErrorKind::SendRequest => {
                let err = self.inner.downcast_ref::<reqwest::Error>().unwrap();
                Some(err)
            },
            PublishUpdateErrorKind::ReadResponse => {
                let err = self.inner.downcast_ref::<reqwest::Error>().unwrap();
                Some(err)
            },
        }
    }
}

impl PublishUpdateError {
    /// Returns the corresponding [`PublishUpdateErrorKind`] for this error.
    #[must_use]
    pub const fn kind(&self) -> &PublishUpdateErrorKind {
        &self.kind
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context as _, Result};

    use super::*;

    #[test]
    fn it_serializes_privacy_if_private() -> Result<()> {
        let canonical_url = "https://example.com/books/1".parse()?;
        let alternate_urls = vec!["https://example.com/users/1/books/1".parse()?];
        let params = PublishUpdateParams {
            topic: Topic::new(canonical_url, alternate_urls),
            data: None,
            privacy: PublishUpdatePrivacy::Private,
        };
        let encoded_params = serde_html_form::to_string(params)
            .context("Failed to serialize parameters to application/x-www-form-urlencoded")?;
        assert_eq!(
            encoded_params,
            "topic=https%3A%2F%2Fexample.com%2Fbooks%2F1&topic=https%3A%2F%2Fexample.com%2Fusers%\
             2F1%2Fbooks%2F1&private=on"
        );
        Ok(())
    }

    #[test]
    fn it_skips_serializing_privacy_if_public() -> Result<()> {
        let canonical_url = "https://example.com/books/1".parse()?;
        let alternate_urls = vec![];
        let params = PublishUpdateParams {
            topic: Topic::new(canonical_url, alternate_urls),
            data: None,
            privacy: PublishUpdatePrivacy::Public,
        };
        let encoded_params = serde_html_form::to_string(params)
            .context("Failed to serialize parameters to application/x-www-form-urlencoded")?;
        assert_eq!(
            encoded_params,
            "topic=https%3A%2F%2Fexample.com%2Fbooks%2F1"
        );
        Ok(())
    }
}
