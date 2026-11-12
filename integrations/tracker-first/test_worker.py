import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "tracker_worker_wrapper", Path(__file__).with_name("worker.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("worker module could not be loaded")
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)

WIF_PROVIDER = "projects/123/locations/global/workloadIdentityPools/test/providers/gitlab"


class WorkerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        binary = root / "fullsend"
        binary.write_bytes(b"controlled-test-binary")
        request = {
            "operation_id": "dispatch-1",
            "repository": "https://github.com/example/source",
            "branch": "release/1",
            "source_sha": "a" * 40,
        }
        raw = json.dumps(request, separators=(",", ":")).encode()
        self.env = {
            "CI_PROJECT_DIR": str(root),
            "CI_JOB_ID": "42",
            "CI_COMMIT_REF_PROTECTED": "true",
            "FULLSEND_TRACKER_BINARY": str(binary),
            "FULLSEND_TRACKER_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "TRACKER_REQUEST_B64": base64.b64encode(raw).decode(),
            "TRACKER_REQUEST_DIGEST": hashlib.sha256(raw).hexdigest(),
            "TRACKER_OPERATION_ID": "dispatch-1",
        }

    def test_admission_precedes_source_fetch(self):
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch.object(sys, "argv", ["worker"]),
            patch.object(WORKER.subprocess, "run") as run,
        ):
            run.return_value.returncode = 0
            self.assertEqual(WORKER.main(), 0)
            self.assertIn("--check", run.call_args_list[0].args[0])
            self.assertEqual(run.call_args_list[1].args[0][:2], ["git", "clone"])
            self.assertNotIn("--check", run.call_args_list[-1].args[0])

    def test_failed_admission_does_not_fetch(self):
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch.object(sys, "argv", ["worker"]),
            patch.object(WORKER.subprocess, "run") as run,
        ):
            run.side_effect = subprocess.CalledProcessError(1, "fullsend")
            with self.assertRaises(subprocess.CalledProcessError):
                WORKER.main()
            self.assertEqual(run.call_count, 1)

    def test_integrity_failure_precedes_any_command(self):
        for name in (
            "FULLSEND_TRACKER_BINARY_SHA256",
            "TRACKER_REQUEST_DIGEST",
            "TRACKER_OPERATION_ID",
        ):
            env = {**self.env, name: "wrong"}
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["worker"]),
                patch.object(WORKER.subprocess, "run") as run,
            ):
                with self.assertRaises(ValueError):
                    WORKER.main()
                run.assert_not_called()

    def test_finalizer_skips_finished_attempt_without_inference(self):
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch.object(sys, "argv", ["worker", "--finalize-only"]),
            patch.object(WORKER.subprocess, "run") as run,
        ):
            run.return_value.stdout = '{"data":{"state":"assessed"}}'
            self.assertEqual(WORKER.main(), 0)
            self.assertEqual(run.call_count, 1)
            self.assertTrue(all(call.args[0][0] != "git" for call in run.call_args_list))

    def test_debug_or_unprotected_job_is_rejected(self):
        for change in ({"CI_DEBUG_TRACE": "true"}, {"CI_COMMIT_REF_PROTECTED": "false"}):
            with (
                patch.dict(os.environ, {**self.env, **change}, clear=True),
                patch.object(sys, "argv", ["worker"]),
                self.assertRaises(ValueError),
            ):
                WORKER.main()


class VertexEnvironmentTests(unittest.TestCase):
    def test_existing_routes_are_preserved_without_wif(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"EXISTING": "value"}, clear=True),
        ):
            with WORKER.inference_environment(Path(directory)) as env:
                self.assertEqual(env, {"EXISTING": "value"})
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_wif_files_are_private_and_removed(self):
        values = {
            "FULLSEND_GCP_WIF_PROVIDER": WIF_PROVIDER,
            "FULLSEND_GCP_PROJECT_ID": "test-project",
            "FULLSEND_ID_TOKEN": "synthetic-identity",
            "FULLSEND_GCP_SERVICE_ACCOUNT": "runner@test-project.iam.gserviceaccount.com",
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, values, clear=True):
            with WORKER.inference_environment(Path(directory)) as env:
                token = Path(env["GCP_OIDC_TOKEN_FILE"])
                credentials = Path(env["GOOGLE_APPLICATION_CREDENTIALS"])
                self.assertEqual(token.read_text(), "synthetic-identity")
                self.assertEqual(token.stat().st_mode & 0o777, 0o600)
                data = json.loads(credentials.read_text())
                self.assertEqual(
                    data["credential_source"]["file"], "/sandbox/workspace/.gcp-oidc-token"
                )
                self.assertIn("service_account_impersonation_url", data)
                self.assertEqual(env["GOOGLE_CLOUD_PROJECT"], "test-project")
            self.assertFalse(token.exists())
            self.assertFalse(credentials.exists())

    def test_invalid_inference_identity_creates_no_files(self):
        for values in (
            {"FULLSEND_GCP_WIF_PROVIDER": "invalid"},
            {
                "FULLSEND_GCP_WIF_PROVIDER": WIF_PROVIDER,
                "FULLSEND_GCP_PROJECT_ID": "test-project",
                "FULLSEND_ID_TOKEN": "synthetic",
                "FULLSEND_GCP_SERVICE_ACCOUNT": "invalid/account",
            },
        ):
            with (
                tempfile.TemporaryDirectory() as directory,
                patch.dict(os.environ, values, clear=True),
            ):
                with self.assertRaises(ValueError), WORKER.inference_environment(Path(directory)):
                    self.fail("invalid identity admitted")
                self.assertEqual(list(Path(directory).iterdir()), [])
