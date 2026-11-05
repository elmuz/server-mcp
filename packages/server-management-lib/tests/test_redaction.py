"""Tests for the file-content redaction helpers."""

import pytest

from server_management_lib.redaction import REDACTED_VALUE, redact_env_content


class TestRedactEnvContent:
    def test_values_are_masked(self):
        text = "DB_PASSWORD=hunter2\nAPI_TOKEN=abc123\n"

        result = redact_env_content(text)

        assert "hunter2" not in result
        assert "abc123" not in result
        assert result == f"DB_PASSWORD={REDACTED_VALUE}\nAPI_TOKEN={REDACTED_VALUE}\n"

    def test_keys_comments_and_blank_lines_are_preserved(self):
        text = "# compose stack\n\nDB_HOST=db\nexport DB_NAME=app # inline\n"

        result = redact_env_content(text)

        assert result.splitlines()[:2] == ["# compose stack", ""]
        assert "DB_HOST=" in result
        assert "db\n" not in result
        assert "export DB_NAME=" in result
        assert "app # inline" not in result

    def test_commented_credentials_are_masked(self):
        text = "# compose stack\n# API_TOKEN=commented-secret\nDB_HOST=db\n"

        result = redact_env_content(text)

        assert "# compose stack" in result
        assert "# API_TOKEN=***" in result
        assert "commented-secret" not in result
        assert "DB_HOST=***" in result

    def test_quoted_and_spaced_values_are_masked(self):
        text = 'A="secret value"\nB = spaced\nC=\n'

        result = redact_env_content(text)

        assert (
            result == f"A={REDACTED_VALUE}\nB = {REDACTED_VALUE}\nC={REDACTED_VALUE}\n"
        )

    def test_unrecognized_lines_are_masked(self):
        text = "no assignment here\n\n  indented text\n"

        assert redact_env_content(text) == f"{REDACTED_VALUE}\n\n{REDACTED_VALUE}\n"

    def test_multiline_quoted_values_do_not_leak(self):
        text = (
            'PRIVATE_KEY="-----BEGIN KEY-----\nMIIsecretmaterial\n-----END KEY-----"\n'
        )

        result = redact_env_content(text)

        assert "MIIsecretmaterial" not in result
        assert result.splitlines() == [f"PRIVATE_KEY={REDACTED_VALUE}", "***", "***"]

    def test_trailing_newline_is_reported_consistently(self):
        assert redact_env_content("A=1").endswith("A=***")
        assert redact_env_content("A=1\n").endswith("A=***\n")

    def test_empty_input(self):
        assert redact_env_content("") == ""


class TestRedactSecrets:
    """General service-file and host-output redaction (P1-17)."""

    def test_compose_style_assignments_are_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = (
            "services:\n"
            "  db:\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: hunter2\n"
            "      NORMAL_SETTING: visible\n"
            "      - API_TOKEN=abc123\n"
        )

        result = redact_secrets(text)

        assert "POSTGRES_PASSWORD: ***" in result
        assert "NORMAL_SETTING: visible" in result
        assert "- API_TOKEN=***" in result
        assert "hunter2" not in result
        assert "abc123" not in result

    def test_json_member_is_masked_and_structure_preserved(self):
        from server_management_lib.redaction import redact_secrets

        text = '{"name": "app", "token": "json-secret", "count": 1}'

        result = redact_secrets(text)

        assert '"name": "app"' in result
        assert '"token": "***"' in result
        assert '"count": 1' in result
        assert "json-secret" not in result

    def test_bearer_and_jwt_values_are_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = (
            "Authorization: Bearer abc.def.ghi\n"
            "access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\n"
        )

        result = redact_secrets(text)

        assert "abc.def.ghi" not in result
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "Authorization: ***" in result

    def test_command_line_flags_are_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = "Command: /usr/bin/app --token tok_123 --name bob -e DB_PASSWORD=x"

        result = redact_secrets(text)

        assert "--token ***" in result
        assert "--name bob" in result
        assert "DB_PASSWORD=***" in result
        assert "tok_123" not in result

    def test_url_credentials_are_masked(self):
        from server_management_lib.redaction import redact_secrets

        result = redact_secrets("postgres://user:pass@db/app")

        assert result == "postgres://user:***@db/app"

    def test_auth_prefixed_diagnostics_stay_readable(self):
        from server_management_lib.redaction import redact_secrets

        text = "AUTH_TYPE: basic\nAUTH_USERNAME: bob\nAUTH_MODE: ldap\n"

        assert redact_secrets(text) == text

    def test_commented_credentials_are_masked_but_comments_stay_readable(self):
        from server_management_lib.redaction import redact_secrets

        text = (
            "# compose stack\n"
            "# API_TOKEN=commented-secret\n"
            "# token=comment\n"
            "monkey.txt is readable\n"
        )

        result = redact_secrets(text)

        assert "# compose stack" in result
        assert "# API_TOKEN=***" in result
        assert "# token=***" in result
        assert "commented-secret" not in result
        assert "comment" not in result
        assert "monkey.txt is readable" in result

    def test_yaml_block_scalar_secret_is_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = (
            "api_token: |\n  first-secret-line\n  second-secret-line\nname: visible\n"
        )

        result = redact_secrets(text)

        assert "first-secret-line" not in result
        assert "second-secret-line" not in result
        assert result.splitlines() == [
            f"api_token: {REDACTED_VALUE}",
            REDACTED_VALUE,
            REDACTED_VALUE,
            "name: visible",
        ]

    def test_yaml_block_scalar_with_chomping_indicator_is_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = "  db_password: >-\n    folded-secret\n  user: bob\n"

        result = redact_secrets(text)

        assert "folded-secret" not in result
        assert result.splitlines() == [
            f"  db_password: {REDACTED_VALUE}",
            REDACTED_VALUE,
            "  user: bob",
        ]

    def test_non_secret_block_scalar_is_preserved(self):
        from server_management_lib.redaction import redact_secrets

        text = "description: |\n  ordinary text\n  more text\n"

        assert redact_secrets(text) == text

    def test_ini_short_password_key_is_masked(self):
        from server_management_lib.redaction import redact_secrets

        text = "[mail]\npass = hunter2\nuser = bob\n"

        result = redact_secrets(text)

        assert "hunter2" not in result
        assert "[mail]" in result
        assert "user = bob" in result
        assert result.splitlines()[1] == f"pass = {REDACTED_VALUE}"

    @pytest.mark.parametrize(
        "key",
        [
            "pass",
            "PASS",
            "Pass",
            "pw",
            "pwd",
            "passphrase",
            "passwd",
            "db_pass",
            "db-pass",
            "dbpass",
            "smtpPass",
            "api_key",
            "apikey",
            "apiKey",
            "auth_token",
            "authToken",
            "auth",
            "basic_auth",
            "proxy_auth",
            "secret_key",
            "client_secret",
            "credentials",
        ],
    )
    def test_credential_key_spellings_are_masked(self, key):
        from server_management_lib.redaction import redact_secrets

        result = redact_secrets(f"{key} = hunter2")

        assert "hunter2" not in result, f"leaked value for key {key!r}: {result}"
        assert result == f"{key} = {REDACTED_VALUE}"

    @pytest.mark.parametrize(
        "key",
        [
            "user",
            "username",
            "host",
            "port",
            "tokenizer",
            "keyboard",
            "mode",
            "auth_type",
            "AUTH_TYPE",
            "AUTH_USERNAME",
            "auth_mode",
        ],
    )
    def test_non_credential_keys_stay_readable(self, key):
        from server_management_lib.redaction import redact_secrets

        assert redact_secrets(f"{key} = visible") == f"{key} = visible"

    def test_short_password_key_is_masked_in_yaml_and_json(self):
        from server_management_lib.redaction import redact_secrets

        yaml_result = redact_secrets("  pass: hunter2\n")
        json_result = redact_secrets('{"pass": "hunter2"}')

        assert "hunter2" not in yaml_result
        assert f"pass: {REDACTED_VALUE}" in yaml_result
        assert "hunter2" not in json_result
        assert f'"pass": "{REDACTED_VALUE}"' in json_result
