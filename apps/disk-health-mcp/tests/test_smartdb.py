"""
Regression tests for the SMART attribute database.

The database is generated offline by ``scripts/generate_smartdb.py`` and committed.
It must never refresh or rewrite itself at runtime: a previous implementation did
that and silently dropped ``SEAGATE_COMPOSITE``, which disabled Seagate composite
decoding.
"""

from pathlib import Path

from disk_health_mcp import smartdb
from disk_health_mcp.smart_parser import SEAGATE_COMPOSITE_ATTRS


class TestSmartDbContents:
    def test_seagate_composite_constant_present(self):
        assert smartdb.SEAGATE_COMPOSITE == {1, 7, 10}

    def test_seagate_composite_attrs_include_constant(self):
        assert smartdb.SEAGATE_COMPOSITE <= SEAGATE_COMPOSITE_ATTRS

    def test_known_attributes_have_canonical_names(self):
        assert smartdb.SMART_ATTR[5].name == "Reallocated_Sector_Ct"
        assert smartdb.SMART_ATTR[197].name == "Current_Pending_Sector"
        assert smartdb.SMART_ATTR[194].encoding == "tempminmax"
        assert smartdb.SMART_ATTR_NAMES[194] == "Temperature_Celsius"

    def test_database_is_not_empty(self):
        assert len(smartdb.SMART_ATTR) > 40


class TestNoRuntimeRewrite:
    def test_no_refresh_function(self):
        assert not hasattr(smartdb, "refresh_if_stale")

    def test_module_has_no_network_code(self):
        source = Path(smartdb.__file__).read_text()
        assert "urlopen" not in source
        assert "urllib" not in source

    def test_generator_emits_seagate_composite(self):
        script = (
            Path(smartdb.__file__).parent.parent.parent
            / "scripts"
            / "generate_smartdb.py"
        )
        source = script.read_text()
        assert "SEAGATE_COMPOSITE = {" in source
        assert "refresh_if_stale" not in source
