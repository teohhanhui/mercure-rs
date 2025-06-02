//! A client implementation of the [Mercure protocol].
//!
//! [Mercure protocol]: https://mercure.rocks/spec
//!
//! # Example
//!
//! ```
//! use std::error::Error;
//!
//! use mercure::{HubUrl, PublisherJwt, TopicSelector};
//! use url::Url;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let http_client = reqwest::Client::new();
//!     let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
//!     let publisher_jwt = PublisherJwt::new(
//!         &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
//!         vec![TopicSelector::Wildcard],
//!     )?;
//!
//!     let client = mercure::Client::new(http_client, hub_url, publisher_jwt);
//!     Ok(())
//! }
//! ```
//!
//! # Publishing update to Mercure hub
//!
//! ```no_run
//! use std::error::Error;
//!
//! use mercure::client::PublishUpdatePrivacy;
//! use mercure::{HubUrl, PublisherJwt, Topic, TopicSelector};
//! use url::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     let http_client = reqwest::Client::new();
//!     let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
//!     let publisher_jwt = PublisherJwt::new(
//!         &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
//!         vec![TopicSelector::Wildcard],
//!     )?;
//!
//!     let client = mercure::Client::new(http_client, hub_url, publisher_jwt);
//!
//!     let topic = Topic::new("https://example.com/books/1".parse()?, vec![]);
//!     let data = r#"{"isbn":"9780735218789"}"#;
//!     let privacy = PublishUpdatePrivacy::Public;
//!
//!     client.publish_update(topic, Some(&data), privacy).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Issuing subscriber JWT access token
//!
//! ```
//! use std::error::Error;
//!
//! use mercure::jwt::SubscriberJwtSecret;
//! use mercure::{SubscriberJwt, TopicSelector};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let subscriber_jwt_secret =
//!         SubscriberJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
//!     let subscriber_jwt = SubscriberJwt::new(&subscriber_jwt_secret, None, vec![
//!         TopicSelector::UriTemplate("https://example.com/users/1/books/{book_id}".try_into()?),
//!     ])?;
//!     Ok(())
//! }
//! ```

pub use self::client::{Client, HubUrl};
pub use self::jwt::{PublisherJwt, SubscriberJwt};
pub use self::topic::Topic;
pub use self::topic_selector::TopicSelector;

pub mod client;
pub mod cookie;
pub mod jwt;
pub mod topic;
pub mod topic_selector;

#[doc = include_str!("../../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
