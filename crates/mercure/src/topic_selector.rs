use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use uri_template_system::Template;

/// [The Mercure Protocol, Section 3](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-3)
///
/// > A topic selector is an expression intended to be matched by one or several
/// > topics. A topic selector can also be used to match other topic selectors
/// > for authorization purposes.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub enum TopicSelector {
    /// A topic selector which matches all topics.
    #[serde(rename = "*")]
    Wildcard,
    /// A topic selector which matches by a [URI Template].
    ///
    /// [URI Template]: https://datatracker.ietf.org/doc/html/rfc6570
    ///
    /// # Note
    ///
    /// You should use a [URI Template] in absolute form[^abs], which expands to
    /// a valid [URL].
    ///
    /// This constraint cannot be checked due to the flexibility of [URI
    /// Template], but is important for interoperability.
    ///
    /// [URI Template]: https://datatracker.ietf.org/doc/html/rfc6570
    /// [URL]: https://url.spec.whatwg.org/
    ///
    /// [^abs]: <https://github.com/dunglas/mercure/issues/947#issuecomment-2324959856>
    #[serde(untagged)]
    UriTemplate(UriTemplate),
}

/// A [URI Template].
///
/// [URI Template]: https://datatracker.ietf.org/doc/html/rfc6570
///
/// # Note
///
/// You should use a [URI Template] in absolute form[^abs], which expands to a
/// valid [URL].
///
/// This constraint cannot be checked due to the flexibility of [URI Template],
/// but is important for interoperability.
///
/// [URI Template]: https://datatracker.ietf.org/doc/html/rfc6570
/// [URL]: https://url.spec.whatwg.org/
///
/// [^abs]: <https://github.com/dunglas/mercure/issues/947#issuecomment-2324959856>
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct UriTemplate(String);

/// An error which can be returned when parsing a [`UriTemplate`].
#[derive(Debug)]
#[non_exhaustive]
pub struct ParseUriTemplateError {
    inner: uri_template_system::ParseError,
}

impl fmt::Display for TopicSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => write!(f, "*"),
            Self::UriTemplate(uri_template) => write!(f, "{uri_template}"),
        }
    }
}

impl<'a> TryFrom<&'a str> for UriTemplate {
    type Error = ParseUriTemplateError;

    /// Performs the conversion.
    ///
    /// # Note
    ///
    /// You should use a [URI Template] in absolute form[^abs], which expands to
    /// a valid [URL].
    ///
    /// This constraint cannot be checked due to the flexibility of [URI
    /// Template], but is important for interoperability.
    ///
    /// [URI Template]: https://datatracker.ietf.org/doc/html/rfc6570
    /// [URL]: https://url.spec.whatwg.org/
    ///
    /// [^abs]: <https://github.com/dunglas/mercure/issues/947#issuecomment-2324959856>
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let _template = Template::parse(s).map_err(|err| Self::Error { inner: err })?;

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for UriTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for ParseUriTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse URI Template: {err}", err = self.inner)
    }
}

impl Error for ParseUriTemplateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.inner)
    }
}
