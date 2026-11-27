//! Pure restore-selection planning over caller-supplied metadata.
//!
//! This crate does not inspect files, resolve paths, query an index, or restore data.

use std::error::Error;
use std::fmt;

pub const MAX_ITEMS: usize = 1000;
const MAX_PUBLIC_ERROR_CHARS: usize = 240;

/// Synthetic or caller-projected metadata needed to select a restore entry.
///
/// `destination` must already be the safe display value intended for public output.
/// The parsed suffix is supplied separately so this crate never needs a source path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreCandidate<'a> {
    pub media_type: Option<&'a str>,
    pub suffix: Option<&'a str>,
    pub source_hash: &'a str,
    pub destination: &'a str,
    pub action: &'a str,
    pub status: &'a str,
    pub bytes: u64,
    pub error: Option<&'a str>,
}

/// The public fields of a selected restore entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreItem {
    pub source_hash: String,
    pub destination: String,
    pub action: String,
    pub status: String,
    pub bytes: u64,
    pub error: Option<String>,
}

/// Counts exposed by the existing public restore-plan projection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreCounts {
    pub selected: usize,
    pub errors: usize,
}

/// Public plan projection; it contains no source path or selector-only metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub schema: u8,
    pub status: &'static str,
    pub media_type: String,
    pub conflict: String,
    pub items: Vec<RestoreItem>,
    pub counts: RestoreCounts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreValidationError {
    UnsupportedMediaType(String),
    InvalidLimit,
    UnsupportedConflictPolicy(String),
}

impl fmt::Display for RestoreValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMediaType(media_type) => {
                write!(formatter, "Unsupported restore media type: {media_type}")
            }
            Self::InvalidLimit => {
                write!(
                    formatter,
                    "Restore limit must be between 1 and {MAX_ITEMS}."
                )
            }
            Self::UnsupportedConflictPolicy(conflict) => {
                write!(formatter, "Unsupported restore conflict policy: {conflict}")
            }
        }
    }
}

impl Error for RestoreValidationError {}

/// Select matching entries in incoming order and project only existing public fields.
///
/// The caller supplies parsed media suffixes and already-safe destination display values.
/// A selected entry with status `error` still consumes one slot, as it does in the
/// Python restore planner.
pub fn plan_selection(
    candidates: &[RestoreCandidate<'_>],
    media_type: &str,
    limit: Option<i64>,
    conflict: &str,
) -> Result<RestorePlan, RestoreValidationError> {
    if !matches!(
        media_type,
        "all" | "email" | "gmail_attachment" | "photo" | "video"
    ) {
        return Err(RestoreValidationError::UnsupportedMediaType(
            media_type.to_owned(),
        ));
    }
    if limit.is_some_and(|value| value < 1 || value > MAX_ITEMS as i64) {
        return Err(RestoreValidationError::InvalidLimit);
    }
    if !matches!(conflict, "skip" | "rename" | "overwrite") {
        return Err(RestoreValidationError::UnsupportedConflictPolicy(
            conflict.to_owned(),
        ));
    }

    let selection_limit = limit.unwrap_or(MAX_ITEMS as i64) as usize;
    let mut items = Vec::with_capacity(selection_limit.min(candidates.len()));
    for candidate in candidates {
        if !matches_media(candidate, media_type) {
            continue;
        }
        if items.len() >= selection_limit {
            break;
        }
        items.push(RestoreItem {
            source_hash: candidate.source_hash.to_owned(),
            destination: candidate.destination.to_owned(),
            action: candidate.action.to_owned(),
            status: candidate.status.to_owned(),
            bytes: candidate.bytes,
            error: candidate
                .error
                .filter(|error| !error.is_empty())
                .map(|error| error.chars().take(MAX_PUBLIC_ERROR_CHARS).collect()),
        });
    }

    let counts = RestoreCounts {
        selected: items.len(),
        errors: items.iter().filter(|item| item.status == "error").count(),
    };
    Ok(RestorePlan {
        schema: 1,
        status: "planned",
        media_type: media_type.to_owned(),
        conflict: conflict.to_owned(),
        items,
        counts,
    })
}

fn matches_media(candidate: &RestoreCandidate<'_>, selected: &str) -> bool {
    match selected {
        "all" => true,
        "email" => {
            candidate.media_type == Some("email")
                || candidate
                    .suffix
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".eml"))
        }
        media_type => candidate.media_type == Some(media_type),
    }
}
