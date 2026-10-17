"""Tests for output sanitization and size limits."""

from server_management_lib.output import sanitize_output, strip_ansi


class TestStripAnsi:
    def test_color_codes_removed(self):
        assert strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_cursor_and_osc_sequences_removed(self):
        text = "\x1b[2J\x1b]8;;https://example.com\x07link\x1b]8;;\x07"
        assert strip_ansi(text) == "link"

    def test_plain_text_unchanged(self):
        assert strip_ansi("plain text") == "plain text"


class TestSanitizeOutput:
    def test_control_characters_removed_but_whitespace_kept(self):
        text = "a\x00b\x01c\td\ne\rf"
        assert sanitize_output(text) == "abc\td\ne\rf"

    def test_short_output_unchanged(self):
        assert sanitize_output("hello", 100) == "hello"

    def test_output_truncated_with_marker(self):
        result = sanitize_output("x" * 50, 10)
        assert result.startswith("x" * 10)
        assert "truncated to 10 bytes" in result

    def test_truncation_is_utf8_safe(self):
        result = sanitize_output("é" * 10, 5)
        assert "truncated" in result
        # No UnicodeDecodeError / replacement characters
        assert "\ufffd" not in result

    def test_zero_limit_disables_truncation(self):
        assert sanitize_output("x" * 50, 0) == "x" * 50
