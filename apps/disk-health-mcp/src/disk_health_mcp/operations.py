"""
Operation catalog for the disk-health MCP.

Every host command is an argv vector rendered with :func:`shlex.join`. Device
names and test types are validated first, then substituted literally, so no
user-controlled value can become shell syntax.
"""

from server_management_lib import SNAPRAID_STATUS_SUDO_ARGV, Operation

# Absolute paths are required: non-interactive SSH sessions usually do not put
# /usr/sbin on PATH, so a bare ``smartctl`` fails even when it is installed.
SMARTCTL_PATH = "/usr/sbin/smartctl"
NVME_CLI_PATH = "/usr/sbin/nvme"

LIST_DISKS = Operation(
    ("lsblk", "-d", "-o", "NAME,MODEL,SERIAL,SIZE,TYPE,TRAN", "--json")
)

SMART_JSON = Operation((SMARTCTL_PATH, "-j", "-a", "/dev/$device"))
SMART_TEXT = Operation((SMARTCTL_PATH, "-a", "/dev/$device"))
NVME_SMART_LOG = Operation((NVME_CLI_PATH, "smart-log", "/dev/$device"))

# Pre-flight that only reports the smartctl version: it never opens a block
# device, so it cannot spin up a sleeping disk.
SMART_VERSION = Operation((SMARTCTL_PATH, "--version"))

# ``-n standby`` makes smartctl skip the test when the disk is sleeping instead
# of spinning it up. A skipped test exits with status 2, which the tool reports
# explicitly. The operator must wake the disk before requesting the test.
SMART_TEST = Operation(
    (SMARTCTL_PATH, "-n", "standby", "-t", "$test_type", "/dev/$device"),
    read_only=False,
)

# ``snapraid status`` has to run as root: SnapRAID creates the content file and
# its ``<content>.lock`` as ``root:root 0600``, which the unprivileged executor
# cannot read, and ACLs do not survive the 0600 temp file SnapRAID renames over
# the content file. The host sudoers rule allows exactly this argv; the command
# policy in server_management_lib accepts the same literal and nothing else.
SNAPRAID_STATUS = Operation(SNAPRAID_STATUS_SUDO_ARGV)

# mergerFS exposes its pool as a fuse.mergerfs mount. ``--real`` hides the
# virtual filesystems (proc, sysfs, tmpfs) so the table stays readable.
FINDMNT_MOUNTS = Operation(
    (
        "findmnt",
        "--real",
        "-o",
        "TARGET,SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%",
    )
)
FINDMNT_MERGERFS = Operation(
    ("findmnt", "-t", "fuse.mergerfs", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
)
DF_REAL_FILESYSTEMS = Operation(
    ("df", "-h", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs")
)

ZPOOL_STATUS = Operation(("zpool", "status", "-x"))
ZPOOL_LIST = Operation(("zpool", "list", "-o", "name,size,alloc,free,cap,dedup,health"))

CAT_MDSTAT = Operation(("cat", "/proc/mdstat"))
MDADM_DETAIL = Operation(("mdadm", "--detail", "--scan", "--verbose"))

IOSTAT = Operation(("iostat", "-x", "1", "1"))
