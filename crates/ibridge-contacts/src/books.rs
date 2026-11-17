// SPDX-License-Identifier: Apache-2.0

//! The address-book home, its books and the cards in them.

use http::{Method, Request, StatusCode};
use ibridge_core::{CoreError, ETag, ResourcePath};
use ibridge_dav::multistatus::{self, Entry};
use ibridge_dav::{CollectionHome, Exchange};

use crate::CardDavProvider;

/// A card as the server holds it.
pub(crate) struct Fetched {
    pub(crate) etag: ETag,
    pub(crate) text: String,
}

pub(crate) const VCARD_TYPE: &str = "text/vcard; charset=utf-8";

pub(crate) fn protocol() -> CoreError {
    CoreError::Protocol(String::new())
}

/// Maps a failed status to the error the caller should see.
pub(crate) fn status_error(status: StatusCode) -> CoreError {
    match status {
        StatusCode::NOT_FOUND | StatusCode::GONE => CoreError::NotFound,
        StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => CoreError::Conflict,
        StatusCode::UNAUTHORIZED => CoreError::Auth,
        StatusCode::FORBIDDEN => CoreError::Forbidden,
        _ => protocol(),
    }
}

/// Reads a 207 multistatus response into its entries.
pub(crate) fn multistatus(exchange: &Exchange) -> Result<Vec<Entry>, CoreError> {
    if exchange.status.as_u16() != 207 {
        return Err(status_error(exchange.status));
    }
    multistatus::parse(&exchange.body).map_err(|_| protocol())
}

impl CardDavProvider {
    pub(crate) async fn home(&self) -> Result<CollectionHome, CoreError> {
        Ok(self.client.contacts_home().await?)
    }

    /// The address books under `home`.
    pub(crate) async fn books(
        &self,
        home: &CollectionHome,
    ) -> Result<Vec<ResourcePath>, CoreError> {
        const BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <D:propfind xmlns:D=\"DAV:\"><D:prop><D:resourcetype/></D:prop></D:propfind>";
        let request = Request::builder()
            .method("PROPFIND")
            .uri(home.url.as_str())
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(BODY.to_owned())
            .map_err(|_| protocol())?;
        let entries = multistatus(&self.client.request(request).await?)?;
        Ok(entries
            .iter()
            .filter(|entry| entry.is_address_book)
            .filter_map(|entry| home.relative(&entry.href))
            .filter_map(|relative| ResourcePath::try_from(relative.as_str()).ok())
            .collect())
    }

    /// Every card of `book` with its `ETag`. The server filters nothing: its
    /// query filters are unreliable, so callers filter on their side.
    pub(crate) async fn cards(
        &self,
        home: &CollectionHome,
        book: &ResourcePath,
    ) -> Result<Vec<Entry>, CoreError> {
        const BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <C:addressbook-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
            <D:prop><D:getetag/><C:address-data/></D:prop></C:addressbook-query>";
        let request = Request::builder()
            .method("REPORT")
            .uri(home.url_of(book.as_str()))
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(BODY.to_owned())
            .map_err(|_| protocol())?;
        multistatus(&self.client.request(request).await?)
    }

    /// Reads one card with its `ETag`.
    pub(crate) async fn fetch(&self, path: &ResourcePath) -> Result<Fetched, CoreError> {
        let home = self.home().await?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(home.url_of(path.as_str()))
            .body(String::new())
            .map_err(|_| protocol())?;
        let exchange = self.client.request(request).await?;
        if !exchange.status.is_success() {
            return Err(status_error(exchange.status));
        }
        let etag = exchange
            .headers
            .get(http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ETag::try_from(value).ok())
            .ok_or_else(protocol)?;
        let text = String::from_utf8(exchange.body.to_vec()).map_err(|_| protocol())?;
        Ok(Fetched { etag, text })
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use ibridge_core::CoreError;

    use super::status_error;

    #[test]
    fn a_403_with_a_dav_error_body_is_a_permission_error_not_a_login_failure() {
        assert_eq!(status_error(StatusCode::FORBIDDEN), CoreError::Forbidden);
        assert_eq!(status_error(StatusCode::UNAUTHORIZED), CoreError::Auth);
    }
}
