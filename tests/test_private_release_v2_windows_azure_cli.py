import subprocess
import unittest
from unittest import mock

from scripts import private_release_v2_bootstrap as bootstrap


class AzureCliExecutableTests(unittest.TestCase):
    def run_az_json_for_platform(self, platform):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"status":"ok"}',
            stderr="",
        )
        with (
            mock.patch.object(bootstrap.sys, "platform", platform),
            mock.patch.object(
                bootstrap.subprocess, "run", return_value=completed
            ) as runner,
        ):
            document = bootstrap.AzureCliRestSession._run_az_json(
                ["account", "show"], "account inspection"
            )
        return document, runner.call_args

    def test_windows_uses_azure_cli_cmd_launcher(self):
        document, call = self.run_az_json_for_platform("win32")
        self.assertEqual(document, {"status": "ok"})
        self.assertEqual(
            call.args[0],
            ["az.cmd", "account", "show", "--output", "json"],
        )
        self.assertFalse(call.kwargs["check"])
        self.assertEqual(call.kwargs["timeout"], 45)

    def test_non_windows_keeps_extensionless_azure_cli_launcher(self):
        _, call = self.run_az_json_for_platform("linux")
        self.assertEqual(call.args[0][0], "az")

    def test_launch_failures_are_generic_and_never_fall_back(self):
        failures = (
            FileNotFoundError("sensitive local executable path"),
            subprocess.TimeoutExpired(["az.cmd"], 45, stderr="secret stderr"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with (
                    mock.patch.object(bootstrap.sys, "platform", "win32"),
                    mock.patch.object(
                        bootstrap.subprocess, "run", side_effect=failure
                    ) as runner,
                    self.assertRaisesRegex(
                        bootstrap.BootstrapError,
                        "^Azure CLI account inspection failed$",
                    ),
                ):
                    bootstrap.AzureCliRestSession._run_az_json(
                        ["account", "show"], "account inspection"
                    )
                runner.assert_called_once()
                self.assertEqual(runner.call_args.args[0][0], "az.cmd")

    def test_nonzero_result_does_not_disclose_stderr(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="sensitive Azure CLI diagnostic",
        )
        with (
            mock.patch.object(bootstrap.sys, "platform", "win32"),
            mock.patch.object(bootstrap.subprocess, "run", return_value=completed),
            self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "^Azure CLI token acquisition failed$",
            ),
        ):
            bootstrap.AzureCliRestSession._run_az_json(
                ["account", "get-access-token"], "token acquisition"
            )


if __name__ == "__main__":
    unittest.main()
