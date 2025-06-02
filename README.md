# mercure-rs

[![crates.io](https://img.shields.io/crates/v/mercure.svg)](https://crates.io/crates/mercure)
[![Documentation](https://docs.rs/mercure/badge.svg)](https://docs.rs/mercure)
![License](https://img.shields.io/crates/l/mercure.svg)

A client implementation of the [Mercure protocol].

[Mercure protocol]: https://mercure.rocks/spec


# Example

```rust
use std::error::Error;

use mercure::{HubUrl, PublisherJwt, TopicSelector};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    let http_client = reqwest::Client::new();
    let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
    let publisher_jwt = PublisherJwt::new(
        &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
        vec![TopicSelector::Wildcard],
    )?;

    let client = mercure::Client::new(http_client, hub_url, publisher_jwt);
    Ok(())
}
```

# Publishing update to Mercure hub

```rust,no_run
use std::error::Error;

use mercure::client::PublishUpdatePrivacy;
use mercure::{HubUrl, PublisherJwt, Topic, TopicSelector};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let http_client = reqwest::Client::new();
    let hub_url = HubUrl::try_from("https://localhost/.well-known/mercure".parse::<Url>()?)?;
    let publisher_jwt = PublisherJwt::new(
        &b"!ChangeThisMercureHubJWTSecretKey!".to_vec().into(),
        vec![TopicSelector::Wildcard],
    )?;

    let client = mercure::Client::new(http_client, hub_url, publisher_jwt);

    let topic = Topic::new("https://example.com/books/1".parse()?, vec![]);
    let data = r#"{"isbn":"9780735218789"}"#;
    let privacy = PublishUpdatePrivacy::Public;

    client.publish_update(topic, Some(&data), privacy).await?;
    Ok(())
}
```

# Issuing subscriber JWT access token

```rust
use std::error::Error;

use mercure::jwt::SubscriberJwtSecret;
use mercure::{SubscriberJwt, TopicSelector};

fn main() -> Result<(), Box<dyn Error>> {
    let subscriber_jwt_secret =
        SubscriberJwtSecret::from(b"!ChangeThisMercureHubJWTSecretKey!".to_vec());
    let subscriber_jwt = SubscriberJwt::new(&subscriber_jwt_secret, None, vec![
        TopicSelector::UriTemplate("https://example.com/users/1/books/{book_id}".try_into()?),
    ])?;
    Ok(())
}
```

## License

Licensed under either of

* Apache License, Version 2.0
    ([LICENSE-APACHE] or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license
    ([LICENSE-MIT] or <https://opensource.org/license/MIT>)

at your option.

[LICENSE-APACHE]: LICENSE-APACHE
[LICENSE-MIT]: LICENSE-MIT

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
