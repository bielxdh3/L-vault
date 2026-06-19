from pathlib import Path

from localvault.email_names import friendly_email_filename, sanitize_filename_component, unique_friendly_email_path


def test_friendly_email_filename_uses_date_sender_subject_and_id():
    name = friendly_email_filename(
        message_date="Fri, 19 Jun 2026 13:10:00 -0400",
        sender="Claudio <claudio@example.com>",
        subject='Relatorio: LocalVault / teste?',
        unique_id="abc123",
    )
    assert name.startswith("2026-06-19_1710__Claudio__")
    assert name.endswith("__abc123.eml")
    assert ":" not in name
    assert "/" not in name
    assert "?" not in name


def test_sanitize_filename_component_handles_windows_reserved_names():
    assert sanitize_filename_component("CON", "fallback") == "CON_file"
    assert sanitize_filename_component('a<b>c:d/e\\f|g?h*i', "fallback") == "a_b_c_d_e_f_g_h_i"


def test_unique_friendly_email_path_avoids_duplicate_names(tmp_path: Path):
    first = unique_friendly_email_path(tmp_path, message_date=None, sender="Ana", subject="Oi", unique_id="same")
    first.write_text("one", encoding="utf-8")
    second = unique_friendly_email_path(tmp_path, message_date=None, sender="Ana", subject="Oi", unique_id="same")
    assert second != first
    assert second.stem.endswith("_1")
