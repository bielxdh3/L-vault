use lvault_restore_selection::{
    MAX_ITEMS, RestoreCandidate, RestoreItem, RestoreValidationError, plan_selection,
};

fn row<'a>(
    media_type: Option<&'a str>,
    suffix: Option<&'a str>,
    source_hash: &'a str,
    destination: &'a str,
    status: &'a str,
    error: Option<&'a str>,
) -> RestoreCandidate<'a> {
    RestoreCandidate {
        media_type,
        suffix,
        source_hash,
        destination,
        action: "copy",
        status,
        bytes: 0,
        error,
    }
}

#[test]
fn validates_python_restore_option_values_and_limit_bounds() {
    for media in ["all", "email", "gmail_attachment", "photo", "video"] {
        assert!(plan_selection(&[], media, Some(1), "skip").is_ok());
    }
    for conflict in ["skip", "rename", "overwrite"] {
        assert!(plan_selection(&[], "all", Some(1000), conflict).is_ok());
    }

    let invalid_media = plan_selection(&[], "audio", None, "skip").unwrap_err();
    assert_eq!(
        invalid_media,
        RestoreValidationError::UnsupportedMediaType("audio".to_owned())
    );
    assert_eq!(
        plan_selection(&[], "all", Some(0), "skip").unwrap_err(),
        RestoreValidationError::InvalidLimit
    );
    assert_eq!(
        plan_selection(&[], "all", Some(-1_i64), "skip").unwrap_err(),
        RestoreValidationError::InvalidLimit
    );
    assert_eq!(
        plan_selection(&[], "all", Some(1001), "skip").unwrap_err(),
        RestoreValidationError::InvalidLimit
    );
    assert_eq!(
        plan_selection(&[], "all", None, "merge").unwrap_err(),
        RestoreValidationError::UnsupportedConflictPolicy("merge".to_owned())
    );
    assert_eq!(MAX_ITEMS, 1000);
}

#[test]
fn selects_matching_rows_in_input_order_and_email_suffix_fallback_is_case_insensitive() {
    let rows = [
        row(
            Some("email"),
            Some(".eml"),
            "message",
            "2026/message.eml",
            "planned",
            Some(""),
        ),
        row(
            Some("gmail_attachment"),
            Some(".bin"),
            "attachment",
            "attachment.bin",
            "planned",
            None,
        ),
        row(
            Some("photo"),
            Some(".jpg"),
            "photo",
            "2026/01/photo.jpg",
            "planned",
            None,
        ),
        row(
            Some("video"),
            Some(".mp4"),
            "video",
            "2026/01/video.mp4",
            "planned",
            None,
        ),
        row(
            None,
            Some(".EML"),
            "legacy-email",
            "legacy.eml",
            "planned",
            None,
        ),
    ];
    let rows = [
        RestoreCandidate {
            action: "skip",
            status: "skipped",
            ..rows[0]
        },
        rows[1],
        rows[2],
        rows[3],
        rows[4],
    ];

    let plan = plan_selection(&rows, "email", Some(2), "skip").unwrap();
    assert_eq!(plan.schema, 1);
    assert_eq!(plan.status, "planned");
    assert_eq!(plan.media_type, "email");
    assert_eq!(plan.conflict, "skip");
    assert_eq!(
        plan.items
            .iter()
            .map(|item| item.source_hash.as_str())
            .collect::<Vec<_>>(),
        ["message", "legacy-email"]
    );
    assert_eq!(plan.items[0].destination, "2026/message.eml");
    assert_eq!(plan.items[0].action, "skip");
    assert_eq!(plan.items[0].status, "skipped");
    assert_eq!(plan.items[0].error, None);

    let photos = plan_selection(&rows, "photo", None, "skip").unwrap();
    assert_eq!(photos.items.len(), 1);
    assert_eq!(photos.items[0].source_hash, "photo");
}

#[test]
fn premarked_error_rows_count_toward_the_selection_limit_and_statuses_survive() {
    let rows = [
        row(
            Some("photo"),
            Some(".jpg"),
            "broken",
            "broken.jpg",
            "error",
            Some("source missing"),
        ),
        row(
            Some("photo"),
            Some(".jpg"),
            "ready",
            "ready.jpg",
            "planned",
            None,
        ),
        row(
            Some("photo"),
            Some(".jpg"),
            "later",
            "later.jpg",
            "planned",
            None,
        ),
    ];

    let plan = plan_selection(&rows, "photo", Some(2), "rename").unwrap();
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.items[0].status, "error");
    assert_eq!(plan.items[0].action, "copy");
    assert_eq!(plan.items[1].status, "planned");
    assert_eq!(plan.counts.selected, 2);
    assert_eq!(plan.counts.errors, 1);
}

#[test]
fn omitted_limit_defaults_to_one_thousand_and_public_items_keep_only_public_fields() {
    let rows = (0..=MAX_ITEMS)
        .map(|index| {
            let suffix = if index == 0 { Some(".EML") } else { None };
            let error = if index == 0 {
                "é".repeat(241)
            } else {
                String::new()
            };
            (index.to_string(), suffix, error)
        })
        .collect::<Vec<_>>();
    let candidates = rows
        .iter()
        .map(|(index, suffix, error)| RestoreCandidate {
            media_type: Some("email"),
            suffix: suffix.as_deref(),
            source_hash: index,
            destination: "message.eml",
            action: "copy",
            status: if *index == "0" { "error" } else { "planned" },
            bytes: 12,
            error: if error.is_empty() {
                None
            } else {
                Some(error.as_str())
            },
        })
        .collect::<Vec<_>>();

    let plan = plan_selection(&candidates, "email", None, "skip").unwrap();
    assert_eq!(plan.items.len(), MAX_ITEMS);
    assert_eq!(plan.counts.selected, MAX_ITEMS);
    assert_eq!(plan.counts.errors, 1);
    assert_eq!(
        plan.items[0],
        RestoreItem {
            source_hash: "0".to_owned(),
            destination: "message.eml".to_owned(),
            action: "copy".to_owned(),
            status: "error".to_owned(),
            bytes: 12,
            error: Some("é".repeat(240)),
        }
    );
}
