"""
SMART attribute reference database.

Auto-generated from smartmontools drivedb.h DEFAULT presets.
Do not edit manually — run scripts/generate_smartdb.py to regenerate.

Generation is an explicit offline step. This module never downloads or rewrites
itself at runtime; the committed copy is the single source of truth.

Sources:
- smartmontools drivedb.h: https://github.com/smartmontools/smartmontools/blob/master/smartmontools/drivedb.h
- Seagate composite decoding: smartmontools source (attributes 1, 7, 10 use 48-bit)

Provides:
- SMART_ATTR: dict[int, SMARTAttr] — attribute ID → (name, encoding, type_hint)
- SMART_ATTR_NAMES: dict[int, str] — attribute ID → canonical name
- SEAGATE_COMPOSITE: set[int] — attributes that use 48-bit composite encoding on Seagate
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SMARTAttr:
    """Canonical SMART attribute metadata from smartmontools drivedb.h."""

    name: str
    encoding: str  # raw48, raw16, raw24(raw8), raw16(raw16), tempminmax, etc.
    type_hint: str  # HDD, SSD, or ""


# Canonical SMART attribute database
# Format: ID -> SMARTAttr(name, encoding, type_hint)

SMART_ATTR: dict[int, SMARTAttr] = {
    1: SMARTAttr("Raw_Read_Error_Rate", "raw48", ""),
    2: SMARTAttr("Throughput_Performance", "raw48", ""),
    3: SMARTAttr("Spin_Up_Time", "raw16(avg16)", ""),
    4: SMARTAttr("Start_Stop_Count", "raw48", ""),
    5: SMARTAttr("Reallocated_Sector_Ct", "raw16(raw16)", ""),
    6: SMARTAttr("Read_Channel_Margin", "raw48", "HDD"),
    7: SMARTAttr("Seek_Error_Rate", "raw48", "HDD"),
    8: SMARTAttr("Seek_Time_Performance", "raw48", "HDD"),
    9: SMARTAttr("Power_On_Hours", "raw24(raw8)", ""),
    10: SMARTAttr("Spin_Retry_Count", "raw48", "HDD"),
    11: SMARTAttr("Calibration_Retry_Count", "raw48", "HDD"),
    12: SMARTAttr("Power_Cycle_Count", "raw48", ""),
    13: SMARTAttr("Read_Soft_Error_Rate", "raw48", ""),
    22: SMARTAttr("Helium_Level", "raw48", "HDD"),
    23: SMARTAttr("Helium_Condition_Lower", "raw48", "HDD"),
    24: SMARTAttr("Helium_Condition_Upper", "raw48", "HDD"),
    175: SMARTAttr("Program_Fail_Count_Chip", "raw48", "SSD"),
    176: SMARTAttr("Erase_Fail_Count_Chip", "raw48", "SSD"),
    177: SMARTAttr("Wear_Leveling_Count", "raw48", "SSD"),
    178: SMARTAttr("Used_Rsvd_Blk_Cnt_Chip", "raw48", "SSD"),
    179: SMARTAttr("Used_Rsvd_Blk_Cnt_Tot", "raw48", "SSD"),
    180: SMARTAttr("Unused_Rsvd_Blk_Cnt_Tot", "raw48", "SSD"),
    181: SMARTAttr("Program_Fail_Cnt_Total", "raw48", ""),
    182: SMARTAttr("Erase_Fail_Count_Total", "raw48", "SSD"),
    183: SMARTAttr("Runtime_Bad_Block", "raw48", ""),
    184: SMARTAttr("End-to-End_Error", "raw48", ""),
    187: SMARTAttr("Reported_Uncorrect", "raw48", ""),
    188: SMARTAttr("Command_Timeout", "raw48", ""),
    189: SMARTAttr("High_Fly_Writes", "raw48", "HDD"),
    190: SMARTAttr("Airflow_Temperature_Cel", "tempminmax", ""),
    191: SMARTAttr("G-Sense_Error_Rate", "raw48", "HDD"),
    192: SMARTAttr("Power-Off_Retract_Count", "raw48", ""),
    193: SMARTAttr("Load_Cycle_Count", "raw48", "HDD"),
    194: SMARTAttr("Temperature_Celsius", "tempminmax", ""),
    195: SMARTAttr("Hardware_ECC_Recovered", "raw48", ""),
    196: SMARTAttr("Reallocated_Event_Count", "raw16(raw16)", ""),
    197: SMARTAttr("Current_Pending_Sector", "raw48", ""),
    198: SMARTAttr("Offline_Uncorrectable", "raw48", ""),
    199: SMARTAttr("UDMA_CRC_Error_Count", "raw48", ""),
    200: SMARTAttr("Multi_Zone_Error_Rate", "raw48", "HDD"),
    201: SMARTAttr("Soft_Read_Error_Rate", "raw48", "HDD"),
    202: SMARTAttr("Data_Address_Mark_Errs", "raw48", "HDD"),
    203: SMARTAttr("Run_Out_Cancel", "raw48", ""),
    204: SMARTAttr("Soft_ECC_Correction", "raw48", ""),
    205: SMARTAttr("Thermal_Asperity_Rate", "raw48", ""),
    206: SMARTAttr("Flying_Height", "raw48", "HDD"),
    207: SMARTAttr("Spin_High_Current", "raw48", "HDD"),
    208: SMARTAttr("Spin_Buzz", "raw48", "HDD"),
    209: SMARTAttr("Offline_Seek_Performnce", "raw48", "HDD"),
    220: SMARTAttr("Disk_Shift", "raw48", "HDD"),
    221: SMARTAttr("G-Sense_Error_Rate", "raw48", "HDD"),
    222: SMARTAttr("Loaded_Hours", "raw48", "HDD"),
    223: SMARTAttr("Load_Retry_Count", "raw48", "HDD"),
    224: SMARTAttr("Load_Friction", "raw48", "HDD"),
    225: SMARTAttr("Load_Cycle_Count", "raw48", "HDD"),
    226: SMARTAttr("Load-in_Time", "raw48", "HDD"),
    227: SMARTAttr("Torq-amp_Count", "raw48", "HDD"),
    228: SMARTAttr("Power-off_Retract_Count", "raw48", ""),
    230: SMARTAttr("Head_Amplitude", "raw48", "HDD"),
    231: SMARTAttr("Temperature_Celsius", "raw48", "HDD"),
    232: SMARTAttr("Available_Reservd_Space", "raw48", ""),
    233: SMARTAttr("Media_Wearout_Indicator", "raw48", "SSD"),
    240: SMARTAttr("Head_Flying_Hours", "raw24(raw8)", "HDD"),
    241: SMARTAttr("Total_LBAs_Written", "raw48", ""),
    242: SMARTAttr("Total_LBAs_Read", "raw48", ""),
    250: SMARTAttr("Read_Error_Retry_Rate", "raw48", ""),
    254: SMARTAttr("Free_Fall_Sensor", "raw48", "HDD"),
}

# Quick lookup: ID -> name
SMART_ATTR_NAMES = {k: v.name for k, v in SMART_ATTR.items()}

# Seagate-specific: these attributes use 48-bit composite encoding
# (upper 24 bits = normalized value, lower 24 bits = raw count)
# Reference: smartmontools smartctl.cpp parse_seagate_raw_value()
SEAGATE_COMPOSITE = {
    1,  # Raw_Read_Error_Rate
    7,  # Seek_Error_Rate
    10,  # Spin_Retry_Count
}
