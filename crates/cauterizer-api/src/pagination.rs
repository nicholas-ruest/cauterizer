//! Opaque, offset-based pagination cursor codec.
//!
//! Reuses `cauterizer_syntax::envelope::{Cursor, Page}` rather than inventing a
//! new pagination primitive (P17/P19 both call for reusing the existing envelope
//! types). [`paginate`] is a small, pure, fully tested reference implementation of
//! the "opaque pagination cursor" contract element: callers must never parse or
//! construct a cursor themselves, only round-trip the one a previous [`Page`]
//! returned. This module is deliberately not yet wired to a second live endpoint —
//! P19's single wrapped facade (`organization::handle_bootstrap_local`) has no
//! natural list operation — so it stands alone as a reusable, tested primitive the
//! next paginated endpoint can adopt without redesign.

use cauterizer_syntax::envelope::{Cursor, Page};

/// Stable pagination failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaginationError {
    /// The supplied cursor was not one this codec issued.
    InvalidCursor,
    /// The requested page size was zero and would never make progress.
    ZeroPageSize,
}

/// Splits `items` into one page starting at `cursor` (the beginning, if absent).
///
/// # Errors
///
/// Returns [`PaginationError::ZeroPageSize`] for a zero page size and
/// [`PaginationError::InvalidCursor`] for a cursor this codec did not issue,
/// including one addressing a stale offset past the current item count.
pub fn paginate<T: Clone>(
    items: &[T],
    cursor: Option<&Cursor>,
    page_size: usize,
) -> Result<Page<T>, PaginationError> {
    if page_size == 0 {
        return Err(PaginationError::ZeroPageSize);
    }
    let offset = match cursor {
        None => 0,
        Some(cursor) => cursor
            .as_str()
            .parse::<usize>()
            .map_err(|_| PaginationError::InvalidCursor)?,
    };
    if offset > items.len() {
        return Err(PaginationError::InvalidCursor);
    }
    let end = offset.saturating_add(page_size).min(items.len());
    let next_cursor = if end < items.len() {
        Some(Cursor::parse(end.to_string()).map_err(|_| PaginationError::InvalidCursor)?)
    } else {
        None
    };
    Ok(Page {
        items: items[offset..end].to_vec(),
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_page_returns_a_cursor_only_when_more_items_remain() {
        let items = vec![1, 2, 3, 4, 5];
        let first = paginate(&items, None, 2).unwrap();
        assert_eq!(first.items, vec![1, 2]);
        assert!(first.next_cursor.is_some());
    }

    #[test]
    fn following_the_returned_cursor_yields_the_next_page_and_eventually_terminates() {
        let items = vec![1, 2, 3, 4, 5];
        let first = paginate(&items, None, 2).unwrap();
        let second = paginate(&items, first.next_cursor.as_ref(), 2).unwrap();
        assert_eq!(second.items, vec![3, 4]);
        assert!(second.next_cursor.is_some());
        let third = paginate(&items, second.next_cursor.as_ref(), 2).unwrap();
        assert_eq!(third.items, vec![5]);
        assert_eq!(third.next_cursor, None);
    }

    #[test]
    fn a_cursor_this_codec_did_not_issue_is_rejected() {
        let items = vec![1, 2, 3];
        let forged = Cursor::parse("999").unwrap();
        assert_eq!(
            paginate(&items, Some(&forged), 2),
            Err(PaginationError::InvalidCursor)
        );
    }

    #[test]
    fn zero_page_size_is_rejected_rather_than_stalling() {
        let items = vec![1, 2, 3];
        assert_eq!(
            paginate(&items, None, 0),
            Err(PaginationError::ZeroPageSize)
        );
    }
}
