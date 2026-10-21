"""Unit tests validating safety guarantees and command blocking."""

import unittest
from realme1_unlock_research.command_runner import CommandSecurityViolation, SafeCommandRunner


class TestCommandRunnerSafety(unittest.TestCase):
    def setUp(self):
        self.runner = SafeCommandRunner()

    def test_safe_commands_allowed(self):
        safe_commands = [
            ["adb", "devices", "-l"],
            ["adb", "shell", "getprop"],
            ["fastboot", "devices"],
            ["lsusb"],
            ["udevadm", "--version"],
            ["python3", "--version"],
        ]
        for cmd in safe_commands:
            try:
                self.runner.validate_safety(cmd)
            except CommandSecurityViolation:
                self.fail(f"Safe command {cmd} was unexpectedly rejected.")

    def test_unsafe_fastboot_commands_blocked(self):
        unsafe_commands = [
            ["fastboot", "flashing", "unlock"],
            ["fastboot", "oem", "unlock"],
            ["fastboot", "flash", "boot", "boot.img"],
            ["fastboot", "erase", "userdata"],
            ["fastboot", "format", "userdata"],
            ["fastboot", "flashing", "lock"],
        ]
        for cmd in unsafe_commands:
            with self.assertRaises(CommandSecurityViolation):
                self.runner.validate_safety(cmd)

    def test_unsafe_disk_utilities_blocked(self):
        unsafe_commands = [
            ["dd", "if=/dev/zero", "of=/dev/block/bootdevice/by-name/boot"],
            ["mkfs.ext4", "/dev/block/by-name/userdata"],
            ["fdisk", "/dev/block/mmcblk0"],
        ]
        for cmd in unsafe_commands:
            with self.assertRaises(CommandSecurityViolation):
                self.runner.validate_safety(cmd)

    def test_runner_returns_safe_error_on_blocked_command(self):
        res = self.runner.run(["fastboot", "flashing", "unlock"])
        self.assertFalse(res.is_safe)
        self.assertEqual(res.exit_code, -1)
        self.assertIn("violates read-only safety", res.stderr)


if __name__ == "__main__":
    unittest.main()
