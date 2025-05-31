use std::iter::{self, Chain, FusedIterator};

use serde::Serialize;
use url::Url;

/// [The Mercure Protocol, Section 5](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure#section-5)
///
/// > The identifiers of the updated topic. It is RECOMMENDED to use an IRI as
/// > identifier. If this name is present several times, the first occurrence is
/// > considered to be the canonical IRI of the topic, and other ones are
/// > considered to be alternate IRIs. The hub MUST dispatch this update to
/// > subscribers that are subscribed to both canonical or alternate IRIs.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Topic {
    canonical_url: Url,
    alternate_urls: Vec<Url>,
}

#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Iter<'a>(Chain<iter::Once<&'a Url>, std::slice::Iter<'a, Url>>);

#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoIter(Chain<iter::Once<Url>, std::vec::IntoIter<Url>>);

impl From<Url> for Topic {
    fn from(canonical_url: Url) -> Self {
        Self {
            canonical_url,
            alternate_urls: Default::default(),
        }
    }
}

impl<'a> IntoIterator for &'a Topic {
    type IntoIter = Iter<'a>;
    type Item = &'a Url;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for Topic {
    type IntoIter = IntoIter;
    type Item = Url;

    /// Creates a consuming iterator, that is, one that moves each topic URL out
    /// of the `Topic`. The `Topic` cannot be used after calling this.
    fn into_iter(self) -> Self::IntoIter {
        IntoIter(iter::once(self.canonical_url).chain(self.alternate_urls))
    }
}

impl Serialize for Topic {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self)
    }
}

impl Topic {
    /// Constructs a new `Topic`.
    pub fn new(canonical_url: Url, alternate_urls: Vec<Url>) -> Self {
        Self {
            canonical_url,
            alternate_urls,
        }
    }

    /// Returns an iterator over the topic URL(s).
    ///
    /// The iterator yields the canonical URL, followed by alternate URLs (if
    /// any).
    pub fn iter(&self) -> Iter<'_> {
        Iter(iter::once(&self.canonical_url).chain(self.alternate_urls.iter()))
    }

    pub fn canonical_url(&self) -> &Url {
        &self.canonical_url
    }

    pub fn alternate_urls(&self) -> &Vec<Url> {
        &self.alternate_urls
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Url;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.0.count()
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.0.last()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n)
    }

    fn fold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.0.fold(acc, f)
    }

    #[inline]
    fn find<P>(&mut self, predicate: P) -> Option<Self::Item>
    where
        P: FnMut(&Self::Item) -> bool,
    {
        self.0.find(predicate)
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n)
    }

    fn rfold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.0.rfold(acc, f)
    }

    #[inline]
    fn rfind<P>(&mut self, predicate: P) -> Option<Self::Item>
    where
        P: FnMut(&Self::Item) -> bool,
    {
        self.0.rfind(predicate)
    }
}

impl<'a> FusedIterator for Iter<'a> {}

impl<'a> ExactSizeIterator for Iter<'a> {}

impl Iterator for IntoIter {
    type Item = Url;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.0.count()
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.0.last()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n)
    }

    fn fold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.0.fold(acc, f)
    }

    #[inline]
    fn find<P>(&mut self, predicate: P) -> Option<Self::Item>
    where
        P: FnMut(&Self::Item) -> bool,
    {
        self.0.find(predicate)
    }
}

impl DoubleEndedIterator for IntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n)
    }

    fn rfold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.0.rfold(acc, f)
    }

    #[inline]
    fn rfind<P>(&mut self, predicate: P) -> Option<Self::Item>
    where
        P: FnMut(&Self::Item) -> bool,
    {
        self.0.rfind(predicate)
    }
}

impl FusedIterator for IntoIter {}

impl ExactSizeIterator for IntoIter {}
