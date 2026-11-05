"""Tests for output sanitization and size limits."""

import asyncio

from server_management_lib.output import (
    BoundedCollector,
    sanitize_output,
    strip_ansi,
    truncation_marker,
)


class _Reader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, size: int = -1) -> bytes:
        if not self._data:
            return b""
        if size < 0:
            chunk, self._data = self._data, b""
            return chunk
        chunk, self._data = self._data[:size], self._data[size:]
        return chunk


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

    def test_truncation_is_idempotent_at_the_same_limit(self):
        once = sanitize_output("x" * 50, 10, label="tool output")
        twice = sanitize_output(once, 10, label="tool output")
        assert twice == once
        assert twice.count("truncated to 10 bytes") == 1

    def test_truncation_marker_matches_sanitize_output(self):
        assert (
            truncation_marker("tool output", 10)
            == "\n… [tool output truncated to 10 bytes]"
        )


class TestBoundedCollector:
    def test_retains_at_most_the_limit(self):
        async def run():
            collector = BoundedCollector(10)
            data = await collector.read(_Reader(b"x" * 100))
            assert data == b"x" * 10
            assert collector.truncated is True

        asyncio.run(run())

    def test_shared_budget_across_streams(self):
        async def run():
            collector = BoundedCollector(10)
            stdout, stderr = await asyncio.gather(
                collector.read(_Reader(b"a" * 8)),
                collector.read(_Reader(b"b" * 8)),
            )
            assert len(stdout) + len(stderr) == 10
            assert collector.truncated is True

        asyncio.run(run())

    def test_budget_exhausted_before_a_later_chunk(self):
        class SmallChunks:
            def __init__(self, data: bytes):
                self._data = data

            async def read(self, size: int = -1) -> bytes:
                if not self._data:
                    return b""
                chunk, self._data = self._data[:4], self._data[4:]
                return chunk

        async def run():
            collector = BoundedCollector(10)
            data = await collector.read(SmallChunks(b"x" * 20))
            assert data == b"x" * 10
            assert collector.truncated is True

        asyncio.run(run())

    def test_zero_limit_disables_the_bound(self):
        async def run():
            collector = BoundedCollector(0)
            data = await collector.read(_Reader(b"x" * 100))
            assert data == b"x" * 100
            assert collector.truncated is False

        asyncio.run(run())
