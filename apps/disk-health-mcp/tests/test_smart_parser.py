"""
SMART Parser Tests

Tests SMART data parsing, manufacturer detection, and severity assessment.
"""

import pytest

from disk_health_mcp.smart_parser import (
    SmartAttribute,
    SmartDevice,
    assess_attribute_severity,
    compute_health_score,
    detect_manufacturer,
    format_smart_summary,
    has_usable_smart_data,
    parse_seagate_raw_value,
    parse_smart_json,
    parse_smart_text,
)

# ============================================================================
# Manufacturer Detection Tests
# ============================================================================


class TestManufacturerDetection:
    """Test drive manufacturer detection."""

    def test_seagate_detection(self):
        """Seagate drives should be detected."""
        models = [
            "ST4000VN008-2DR166",
            "Seagate IronWolf",
            "ST8000NM0055",
            "Exos X18",
        ]
        for model in models:
            name, is_seagate = detect_manufacturer(model)
            assert "Seagate" in name, f"Should detect Seagate: {model}"
            assert is_seagate is True, (
                f"Seagate should use non-standard encoding: {model}"
            )

    def test_wd_detection(self):
        """Western Digital drives should be detected."""
        models = [
            "WDC WD40EFRX-68N32N0",
            "WD Blue SN570",
            "WESTERN DIGITAL RED",
        ]
        for model in models:
            name, is_seagate = detect_manufacturer(model)
            assert "Western" in name or "WD" in name, f"Should detect WD: {model}"
            assert is_seagate is False

    def test_samsung_detection(self):
        """Samsung drives should be detected."""
        models = [
            "Samsung SSD 970 EVO Plus 500GB",
            "MZ-V7S500BW",
            "Samsung SSD 860 EVO 1TB",
            "MZ7KM960HAJR",
        ]
        for model in models:
            name, is_seagate = detect_manufacturer(model)
            assert "Samsung" in name, f"Should detect Samsung: {model}"
            assert is_seagate is False

    def test_unknown_manufacturer(self):
        """Unknown drives should return 'Unknown'."""
        name, is_seagate = detect_manufacturer("GenericDrive XYZ123")
        assert name == "Unknown"
        assert is_seagate is False


# ============================================================================
# Seagate Composite Value Tests
# ============================================================================


class TestSeagateCompositeValues:
    """Test Seagate 48-bit composite value handling."""

    def test_parse_seagate_raw_value(self):
        """Seagate composite values should be decoded."""
        # Seagate Raw_Read_Error_Rate often shows huge raw values
        # e.g., 112577564673 -> actual value is lower 32 bits
        seagate_raw = 112577564673
        decoded = parse_seagate_raw_value(1, seagate_raw)
        assert decoded == seagate_raw & 0xFFFFFFFF

    def test_non_seagate_values_unchanged(self):
        """Non-Seagate composite attributes should not be modified."""
        raw = 12345
        # Attribute 5 (Reallocated_Sector_Ct) is not a Seagate composite
        decoded = parse_seagate_raw_value(5, raw)
        assert decoded == raw

    def test_seagate_critical_attributes(self):
        """Seagate critical attributes should be decoded."""
        seagate_composite = {1, 7, 10, 184, 187, 188, 190, 195, 198, 199, 240}
        for attr_id in seagate_composite:
            raw = 0xFFFFFFFFFFFF  # Max 48-bit value
            decoded = parse_seagate_raw_value(attr_id, raw)
            assert decoded <= 0xFFFFFFFF, f"Attribute {attr_id} should decode to 32-bit"


# ============================================================================
# Severity Assessment Tests
# ============================================================================


class TestSeverityAssessment:
    """Test SMART attribute severity assessment."""

    def test_healthy_attribute(self):
        """Normal attributes should be 'ok'."""
        attr = SmartAttribute(
            attr_id=5,
            name="Reallocated_Sector_Ct",
            flags="PO--CK",
            attr_type="Pre-fail",
            updated="Always",
            when_failed="",
            raw_value=0,
            value=100,
            worst=100,
            thresh=10,
        )
        assert assess_attribute_severity(attr, False) == "ok"

    def test_reallocated_sectors_critical(self):
        """Any reallocated sectors should be critical."""
        attr = SmartAttribute(
            attr_id=5,
            name="Reallocated_Sector_Ct",
            flags="PO--CK",
            attr_type="Pre-fail",
            updated="Always",
            when_failed="",
            raw_value=5,
            value=99,
            worst=99,
            thresh=10,
        )
        assert assess_attribute_severity(attr, False) == "critical"

    def test_value_below_threshold_critical(self):
        """Normalized value below threshold should be critical."""
        attr = SmartAttribute(
            attr_id=9,
            name="Power_On_Hours",
            flags="-O--CK",
            attr_type="Old_age",
            updated="Always",
            when_failed="",
            raw_value=50000,
            value=5,
            worst=5,
            thresh=10,
        )
        assert assess_attribute_severity(attr, False) == "critical"

    def test_value_near_threshold_warning(self):
        """Normalized value near threshold should be warning."""
        attr = SmartAttribute(
            attr_id=5,
            name="Reallocated_Sector_Ct",
            flags="PO--CK",
            attr_type="Pre-fail",
            updated="Always",
            when_failed="",
            raw_value=0,
            value=14,
            worst=14,
            thresh=10,
        )
        assert assess_attribute_severity(attr, False) == "warning"

    def test_prefail_low_value_warning(self):
        """Pre-fail attribute with low value should be warning."""
        attr = SmartAttribute(
            attr_id=9,
            name="Power_On_Hours",
            flags="P---CK",
            attr_type="Pre-fail",
            updated="Always",
            when_failed="",
            raw_value=50000,
            value=40,
            worst=40,
            thresh=10,
        )
        assert assess_attribute_severity(attr, False) == "warning"


# ============================================================================
# Health Score Tests
# ============================================================================


class TestHealthScore:
    """Test health score computation."""

    def test_perfect_health(self):
        """A drive with no issues should score 100."""
        device = SmartDevice(
            overall_health="PASSED",
            attributes=[],
            self_test_log=[],
            temperature=35,
        )
        score = compute_health_score(device)
        assert score == 100

    def test_failed_health_zero(self):
        """Failed SMART status should score 0."""
        device = SmartDevice(
            overall_health="FAILED",
            attributes=[],
        )
        score = compute_health_score(device)
        assert score == 0

    def test_critical_attributes_deduct(self):
        """Critical attributes should significantly reduce score."""
        device = SmartDevice(
            overall_health="PASSED",
            attributes=[
                SmartAttribute(
                    attr_id=5,
                    name="Reallocated_Sector_Ct",
                    raw_value=10,
                    value=90,
                    worst=90,
                    thresh=10,
                    severity="critical",
                ),
                SmartAttribute(
                    attr_id=197,
                    name="Current_Pending_Sector",
                    raw_value=3,
                    value=98,
                    worst=98,
                    thresh=10,
                    severity="critical",
                ),
            ],
            temperature=35,
        )
        score = compute_health_score(device)
        assert score < 60  # Two criticals = -50

    def test_high_temperature_deduct(self):
        """High temperature should reduce score."""
        device = SmartDevice(
            overall_health="PASSED",
            attributes=[],
            temperature=65,
        )
        score = compute_health_score(device)
        assert score < 100

    def test_failed_self_test_deduct(self):
        """Failed self-tests should reduce score."""
        device = SmartDevice(
            overall_health="PASSED",
            attributes=[],
            self_test_log=[
                {"type": "Extended offline", "status": "FAILED", "timestamp": 5000}
            ],
            temperature=35,
        )
        score = compute_health_score(device)
        assert score < 100

    def test_score_bounds(self):
        """Health score should be clamped to 0-100."""
        # Many critical attrs should not go below 0
        device = SmartDevice(
            overall_health="PASSED",
            attributes=[
                SmartAttribute(
                    attr_id=i,
                    name=f"attr_{i}",
                    raw_value=100,
                    value=5,
                    worst=5,
                    thresh=10,
                    severity="critical",
                )
                for i in range(10)
            ],
            temperature=70,
        )
        score = compute_health_score(device)
        assert 0 <= score <= 100


# ============================================================================
# JSON Parsing Tests
# ============================================================================


class TestSmartJSONParsing:
    """Test smartctl JSON output parsing."""

    def test_parse_minimal_json(self):
        """Minimal JSON should parse without error."""
        data = {
            "device": {"name": "/dev/sda"},
            "model_name": "ST4000VN008-2DR166",
            "serial_number": "ZDH12345",
            "firmware_version": "SC60",
            "user_capacity": {"string": "4.00 TB"},
            "smart_status": {"passed": True},
            "smartcapable": True,
            "smart_enabled": {"value": True},
            "power_on_time": {"hours": 15000},
            "power_cycle_count": {"count": 42},
            "temperature": {"current": 35},
            "ata_smart_attributes": {"table": []},
            "ata_smart_self_test_log": {"standard": []},
            "ata_smart_error_log": {"count": 0},
        }
        device = parse_smart_json(data)
        assert device.device_path == "/dev/sda"
        assert device.model == "ST4000VN008-2DR166"
        assert device.serial == "ZDH12345"
        assert device.overall_health == "PASSED"
        assert device.power_on_hours == 15000
        assert device.is_seagate is True
        assert device.health_score == 100

    def test_parse_json_with_critical_attributes(self):
        """JSON with critical attributes should flag them."""
        data = {
            "device": {"name": "/dev/sda"},
            "model_name": "WDC WD40EFRX-68N32N0",
            "serial_number": "WD-WMC7K1234567",
            "firmware_version": "82.00A82",
            "user_capacity": {"string": "4.00 TB"},
            "smart_status": {"passed": True},
            "smartcapable": True,
            "smart_enabled": {"value": True},
            "power_on_time": {"hours": 20000},
            "power_cycle_count": {"count": 100},
            "temperature": {"current": 40},
            "ata_smart_attributes": {
                "table": [
                    {
                        "id": 5,
                        "name": "Reallocated_Sector_Ct",
                        "flags": {"string": "PO--CK", "value": 3},
                        "value": 90,
                        "worst": 85,
                        "thresh": 10,
                        "when_failed": "",
                        "raw": {"value": 15},
                    },
                    {
                        "id": 197,
                        "name": "Current_Pending_Sector",
                        "flags": {"string": "-O--CK", "value": 1},
                        "value": 100,
                        "worst": 100,
                        "thresh": 0,
                        "when_failed": "",
                        "raw": {"value": 3},
                    },
                ]
            },
            "ata_smart_self_test_log": {"standard": []},
            "ata_smart_error_log": {"count": 0},
        }
        device = parse_smart_json(data)
        assert device.is_seagate is False
        assert device.health_score < 100
        assert len(device.warnings) >= 1

    def test_parse_json_with_failed_test(self):
        """JSON with failed self-test should flag it."""
        data = {
            "device": {"name": "/dev/sda"},
            "model_name": "Samsung SSD 970 EVO Plus 500GB",
            "serial_number": "S466NF0K123456",
            "firmware_version": "2B2QEXM7",
            "user_capacity": {"string": "500.11 GB"},
            "smart_status": {"passed": True},
            "smartcapable": True,
            "smart_enabled": {"value": True},
            "power_on_time": {"hours": 5000},
            "power_cycle_count": {"count": 200},
            "temperature": {"current": 45},
            "ata_smart_attributes": {"table": []},
            "ata_smart_self_test_log": {
                "standard": [
                    {
                        "type": {"string": "Extended offline"},
                        "status": {"string": "Completed: read failure"},
                        "lifetime_hours": 4800,
                    }
                ]
            },
            "ata_smart_error_log": {"count": 0},
        }
        device = parse_smart_json(data)
        assert device.health_score < 100
        # Failed self-test should be recorded
        assert any(
            any(kw in t.get("status", "").lower() for kw in ("failed", "failure"))
            for t in device.self_test_log
        )


# ============================================================================
# Summary Formatting Tests
# ============================================================================


class TestSmartTextParsing:
    """Text parsing must fail closed when smartctl did not return data."""

    def test_command_not_found_returns_none(self):
        output = "zsh:1: command not found: smartctl\n\n⚠️ Exit code: 127"
        assert parse_smart_text(output) is None

    def test_empty_output_returns_none(self):
        assert parse_smart_text("") is None

    def test_valid_text_returns_device(self):
        output = (
            "Device Model:     WDC WD40EFRX-68N32N0\n"
            "Serial Number:    WD-WMC7K1234567\n"
            "SMART overall-health self-assessment test result: PASSED\n"
        )
        device = parse_smart_text(output)
        assert device is not None
        assert device.model == "WDC WD40EFRX-68N32N0"
        assert device.overall_health == "PASSED"
        assert has_usable_smart_data(device) is True


class TestSummaryFormatting:
    """Test human-readable summary formatting."""

    def test_empty_device_is_refused(self):
        summary = format_smart_summary(SmartDevice())
        assert "No usable SMART data" in summary
        assert "100/100" not in summary
        assert "No issues detected" not in summary

    def test_healthy_drive_summary(self):
        """A healthy drive should produce a clean summary."""
        device = SmartDevice(
            device_path="/dev/sda",
            model="WDC WD40EFRX-68N32N0",
            serial="WD-WMC7K1234567",
            firmware="82.00A82",
            capacity="4.00 TB",
            device_type="ATA",
            overall_health="PASSED",
            power_on_hours=10000,
            power_cycle_count=50,
            temperature=35,
            health_score=100,
            attributes=[],
            warnings=[],
        )
        summary = format_smart_summary(device)
        assert "/dev/sda" in summary
        assert "WDC WD40EFRX" in summary
        assert "PASSED" in summary
        assert "100/100" in summary
        assert "No issues detected" in summary
        assert "🔴" not in summary
        assert "🟡" not in summary

    def test_critical_drive_summary(self):
        """A drive with issues should produce warnings."""
        device = SmartDevice(
            device_path="/dev/sda",
            model="ST4000VN008-2DR166",
            serial="ZDH12345",
            overall_health="PASSED",
            power_on_hours=30000,
            temperature=58,
            health_score=65,
            attributes=[
                SmartAttribute(
                    attr_id=5,
                    name="Reallocated_Sector_Ct",
                    raw_value=20,
                    value=90,
                    worst=85,
                    thresh=10,
                    severity="critical",
                    note="Raw value: 20 (normalized: 90/10)",
                ),
            ],
            warnings=["Reallocated_Sector_Ct: critical - Raw value: 20"],
            is_seagate=True,
        )
        summary = format_smart_summary(device)
        assert "CRITICAL" in summary
        assert "Seagate" in summary
        assert "48-bit composite" in summary
        assert "Reallocated_Sector_Ct" in summary


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestSmartctlFixtures:
    """Parse captured smartctl JSON shapes instead of hand-built dicts."""

    def _load(self, name):
        import json
        from pathlib import Path

        path = Path(__file__).parent / "data" / name
        return json.loads(path.read_text())

    def test_ata_seagate_smart_support_and_status(self):
        device = parse_smart_json(self._load("smart_ata_seagate.json"))

        assert device.device_type == "ATA"
        assert device.smart_supported is True
        assert device.smart_enabled is True
        assert device.overall_health == "PASSED"
        assert device.temperature == 35
        assert device.power_cycle_count == 42
        assert device.is_seagate is True

    def test_ata_critical_and_healthy_attributes(self):
        device = parse_smart_json(self._load("smart_ata_seagate.json"))
        by_id = {attr.attr_id: attr for attr in device.attributes}

        assert by_id[5].severity == "ok"
        assert by_id[197].severity == "critical"
        assert by_id[194].severity == "ok"

    def test_nvme_device_type(self):
        device = parse_smart_json(self._load("smart_nvme.json"))

        assert device.device_type == "NVMe"
        assert device.smart_supported is True
        assert device.overall_health == "PASSED"

    def test_missing_smart_status_is_unknown_not_failed(self):
        device = parse_smart_json(self._load("smart_unknown_status.json"))

        assert device.overall_health == "UNKNOWN"
        assert device.health_score == 100
        assert device.smart_supported is False
        assert device.warnings == []

    def test_zero_threshold_does_not_false_positive(self):
        attr = SmartAttribute(
            attr_id=9,
            name="Power_On_Hours",
            value=0,
            worst=0,
            thresh=0,
            raw_value=0,
        )
        assert assess_attribute_severity(attr, False) == "ok"
