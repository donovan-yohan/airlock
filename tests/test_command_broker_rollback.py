"""Executable checks for complete-set command rollback checkpoints and recovery."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "command-broker-rollback.sh"

# Representative pre-command-broker files: the configs are the exact base
# examples and the state fixtures retain the v1 request/v1 receipt shape. The
# Go compatibility matrix verifies these protocol shapes with signed records;
# this test proves the shell rollback boundary restores all four files from one
# checkpoint after a current-command mutation. Each target rename is atomic,
# but a multi-directory restore is not crash-atomic as a set.
LEGACY_REQUESTER_CONFIG = (ROOT / "configs" / "requester.example.json").read_bytes()
LEGACY_TRUSTED_CONFIG = b'''{
  "listen":"127.0.0.1:8788", "state_dir":"../../.local/state/airlock/trusted",
  "control_socket":"../../.local/state/airlock/trusted/control.sock", "private_key_file":"trusted.key",
  "requester_url":"https://requester-node.example.invalid", "github_cli_path":"/usr/bin/gh",
  "github_config_dir":"../../.local/state/airlock/gh-config", "execution_timeout":"30s",
  "poll_interval":"2s", "request_max_ttl":"15m", "catalog_ttl":"1h", "receipt_ttl":"24h",
  "allowed_logins":["reviewer@example.invalid"], "capabilities":[{"id":"github:example-owner",
  "display_name":"Example GitHub authority", "adapter":"github.repo.add_collaborator/v1",
  "owner":"example-owner", "collaborator":"example-agent", "permissions":["pull","push"]}]}
'''
LEGACY_REQUESTER_STATE = b'''{"catalog":{"version":"airlock.catalog/v1","profiles":[],"capabilities":[{"id":"github:example-owner","actions":["github.repo.add_collaborator"]}]},"requests":{"req_legacy":{"request":{"version":"airlock.request/v1","capability_id":"github:example-owner","action":"github.repo.add_collaborator","arguments":{"repository":"project","permission":"push"}},"state":"manually_executed","receipts":[{"version":"airlock.receipt/v1","decision":"approved_for_manual_execution"},{"version":"airlock.receipt/v1","decision":"manually_executed"}]}}}\n'''
LEGACY_TRUSTED_STATE = b'''{"requests":{"req_legacy":{"request":{"version":"airlock.request/v1","capability_id":"github:example-owner","action":"github.repo.add_collaborator","arguments":{"repository":"project","permission":"push"}},"state":"manually_executed","receipts":[{"receipt":{"version":"airlock.receipt/v1","decision":"approved_for_manual_execution"},"delivered":true},{"receipt":{"version":"airlock.receipt/v1","decision":"manually_executed"},"delivered":true}]}}}\n'''
CURRENT_REQUESTER_STATE = b'''{"requests":{"req_command":{"request":{"version":"airlock.request/v2","profile_id":"github.command","profile_version":"v1","argv":["api","repos/example-owner/project"]},"state":"pending","receipts":[]}}}\n'''
CURRENT_TRUSTED_STATE = b'''{"requests":{"req_command":{"request":{"version":"airlock.request/v2","profile_id":"github.command","profile_version":"v1","argv":["api","repos/example-owner/project"]},"state":"pending","receipts":[],"attempts":[]}}}\n'''


class CommandBrokerRollbackTests(unittest.TestCase):
    def _temporary_root(self) -> tempfile.TemporaryDirectory[str]:
        # /tmp is deliberately rejected by the rollback ancestry validator: it
        # is sticky and world-writable. Use a disposable private child of this
        # worktree, whose euid-owned read/search-only ancestors are safe anchors.
        return tempfile.TemporaryDirectory(dir=ROOT)

    def _paths(self, root: Path) -> list[Path]:
        requester_config = root / "requester.json"
        trusted_config = root / "trusted.json"
        requester_state = root / "requester-state.json"
        trusted_state = root / "trusted-state.json"
        for path, contents in zip(
            (requester_config, trusted_config, requester_state, trusted_state),
            (LEGACY_REQUESTER_CONFIG, LEGACY_TRUSTED_CONFIG, LEGACY_REQUESTER_STATE, LEGACY_TRUSTED_STATE),
            strict=True,
        ):
            path.write_bytes(contents)
            path.chmod(0o600)
        return [requester_config, trusted_config, requester_state, trusted_state]

    def _run(
        self,
        operation: str,
        paths: list[Path],
        checkpoint: Path,
        *,
        confirmed: bool = True,
        script: Path = SCRIPT,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(script), operation,
        ]
        if confirmed:
            arguments.append("--confirm-services-stopped")
        arguments.extend([
            "--requester-config", str(paths[0]),
            "--trusted-config", str(paths[1]),
            "--requester-state", str(paths[2]),
            "--trusted-state", str(paths[3]),
            "--directory", str(checkpoint),
        ])
        return subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, check=False)

    def test_pre_upgrade_checkpoint_restores_legacy_config_and_state_after_current_command_mutation(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            snapshot = self._run("snapshot", paths, checkpoint)
            self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
            self.assertEqual((checkpoint / "SHA256SUMS").read_text(encoding="utf-8").count("\n"), 4)
            saved = [path.read_bytes() for path in paths]
            for path, contents in zip(
                paths,
                (
                    LEGACY_REQUESTER_CONFIG,
                    (ROOT / "configs" / "trusted.example.json").read_bytes(),
                    CURRENT_REQUESTER_STATE,
                    CURRENT_TRUSTED_STATE,
                ),
                strict=True,
            ):
                path.write_bytes(contents)
                path.chmod(0o600)
            restore = self._run("restore", paths, checkpoint)
            self.assertEqual(restore.returncode, 0, restore.stderr)
            self.assertEqual([path.read_bytes() for path in paths], saved)
            self.assertEqual([path.stat().st_mode & 0o777 for path in paths], [0o600] * 4)
            self.assertNotIn(b"github.command", paths[2].read_bytes())
            self.assertNotIn(b"github.command", paths[3].read_bytes())

    def test_restore_rejects_tampered_or_missing_checkpoint_file_without_target_mutation(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            original_targets = [path.read_bytes() for path in paths]
            (checkpoint / "trusted-state.json").write_text('{"tampered":true}\n', encoding="utf-8")
            self.assertNotEqual(self._run("restore", paths, checkpoint).returncode, 0)
            self.assertEqual([path.read_bytes() for path in paths], original_targets)
            (checkpoint / "requester-state.json").unlink()
            self.assertNotEqual(self._run("restore", paths, checkpoint).returncode, 0)
            self.assertEqual([path.read_bytes() for path in paths], original_targets)

    def test_restore_manifest_must_be_exact_complete_and_lowercase(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            original_targets = [path.read_bytes() for path in paths]
            manifest = checkpoint / "SHA256SUMS"
            valid_lines = manifest.read_text(encoding="utf-8").splitlines()
            invalid_manifests = {
                "partial": "\n".join(valid_lines[:3]) + "\n",
                "duplicate": "\n".join([*valid_lines, valid_lines[0]]) + "\n",
                "extra": "\n".join([*valid_lines, f"{'0' * 64}  unexpected.json"]) + "\n",
                "uppercase": valid_lines[0].upper() + "\n" + "\n".join(valid_lines[1:]) + "\n",
            }
            for name, contents in invalid_manifests.items():
                with self.subTest(name=name):
                    manifest.write_text(contents, encoding="utf-8")
                    manifest.chmod(0o600)
                    result = self._run("restore", paths, checkpoint)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertEqual([path.read_bytes() for path in paths], original_targets)

    def test_snapshot_and_restore_require_explicit_stopped_services_confirmation(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            snapshot = self._run("snapshot", paths, checkpoint, confirmed=False)
            self.assertNotEqual(snapshot.returncode, 0)
            self.assertFalse(checkpoint.exists())
            self.assertIn("--confirm-services-stopped", snapshot.stderr)

            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            for path in paths:
                path.write_bytes(b"newer current state\n")
                path.chmod(0o600)
            before_restore = [path.read_bytes() for path in paths]
            restore = self._run("restore", paths, checkpoint, confirmed=False)
            self.assertNotEqual(restore.returncode, 0)
            self.assertEqual([path.read_bytes() for path in paths], before_restore)

    def test_restore_refuses_dangling_symlink_target(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            paths[1].unlink()
            paths[1].symlink_to(root / "does-not-exist")
            result = self._run("restore", paths, checkpoint)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(paths[1].is_symlink())
            self.assertIn("unsafe restore target", result.stderr)

    @unittest.skipUnless(os.name == "posix", "private POSIX mode checks require Unix")
    def test_rejects_all_group_or_other_file_permission_bits(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            for mode in (0o044, 0o066):
                with self.subTest(mode=oct(mode)):
                    fixture_root = root / f"mode-{mode:o}"
                    fixture_root.mkdir(mode=0o700)
                    paths = self._paths(fixture_root)
                    paths[0].chmod(mode)
                    result = self._run("snapshot", paths, fixture_root / "checkpoint")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unsafe", result.stderr)

    def test_rejects_permissive_source_checkpoint_and_target_parents(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            root.chmod(0o755)
            source_parent = self._run("snapshot", paths, root / "checkpoint")
            self.assertNotEqual(source_parent.returncode, 0)
            root.chmod(0o700)

            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            original_targets = [path.read_bytes() for path in paths]
            checkpoint.chmod(0o755)
            checkpoint_result = self._run("restore", paths, checkpoint)
            self.assertNotEqual(checkpoint_result.returncode, 0)
            self.assertEqual([path.read_bytes() for path in paths], original_targets)
            checkpoint.chmod(0o700)

            target_parent = root / "permissive-target-parent"
            target_parent.mkdir(mode=0o700)
            target = target_parent / "requester.json"
            target.write_bytes(b"must not change\n")
            target.chmod(0o600)
            target_parent.chmod(0o755)
            target_paths = [target, paths[1], paths[2], paths[3]]
            target_result = self._run("restore", target_paths, checkpoint)
            self.assertNotEqual(target_result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"must not change\n")

    def test_rejects_permissive_or_sticky_ancestor_before_snapshot_or_restore(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            safe_paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", safe_paths, checkpoint).returncode, 0)

            for mode in (0o777, 0o1755):
                with self.subTest(mode=oct(mode)):
                    unsafe = root / f"unsafe-{mode:o}"
                    unsafe.mkdir(mode=0o700)
                    private = unsafe / "private"
                    private.mkdir(mode=0o700)
                    unsafe.chmod(mode)
                    paths = self._paths(private)
                    before_restore = [path.read_bytes() for path in paths]

                    snapshot = self._run("snapshot", paths, unsafe / "checkpoint")
                    self.assertNotEqual(snapshot.returncode, 0)
                    self.assertIn("directory ancestry", snapshot.stderr)
                    self.assertFalse((unsafe / "checkpoint").exists())

                    restore = self._run("restore", paths, checkpoint)
                    self.assertNotEqual(restore.returncode, 0)
                    self.assertIn("directory ancestry", restore.stderr)
                    self.assertEqual([path.read_bytes() for path in paths], before_restore)

    def test_restore_refuses_duplicate_or_aliased_targets_before_staging(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            for index, path in enumerate(paths):
                path.write_bytes(f"newer-{index}\n".encode())
                path.chmod(0o600)

            duplicate = [paths[0], paths[0], paths[2], paths[3]]
            before_duplicate = [path.read_bytes() for path in paths]
            duplicate_result = self._run("restore", duplicate, checkpoint)
            self.assertNotEqual(duplicate_result.returncode, 0)
            self.assertIn("duplicate restore target", duplicate_result.stderr)
            self.assertEqual([path.read_bytes() for path in paths], before_duplicate)

            non_clean = Path(f"{root}/../{root.name}/{paths[0].name}")
            non_clean_result = self._run("restore", [non_clean, *paths[1:]], checkpoint)
            self.assertNotEqual(non_clean_result.returncode, 0)
            self.assertIn("non-clean absolute", non_clean_result.stderr)
            self.assertEqual([path.read_bytes() for path in paths], before_duplicate)

            paths[1].unlink()
            os.link(paths[0], paths[1])
            before_alias = [path.read_bytes() for path in paths]
            alias_result = self._run("restore", paths, checkpoint)
            self.assertNotEqual(alias_result.returncode, 0)
            self.assertIn("aliased restore target", alias_result.stderr)
            self.assertEqual([path.read_bytes() for path in paths], before_alias)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "requires a non-root POSIX test user")
    def test_partial_staging_failure_never_replaces_a_target(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            source_paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", source_paths, checkpoint).returncode, 0)

            target_paths: list[Path] = []
            for index in range(4):
                parent = root / f"target-{index}"
                parent.mkdir(mode=0o700)
                target = parent / "state"
                target.write_bytes(f"current-{index}\n".encode())
                target.chmod(0o600)
                target_paths.append(target)
            target_paths[1].parent.chmod(0o500)
            try:
                result = self._run("restore", target_paths, checkpoint)
            finally:
                target_paths[1].parent.chmod(0o700)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no targets were replaced", result.stderr)
            self.assertEqual(
                [path.read_bytes() for path in target_paths],
                [f"current-{index}\n".encode() for index in range(4)],
            )

    def test_recovery_restores_already_replaced_target_after_replace_failure(self) -> None:
        """Fault-inject only a disposable script copy; production PATH stays fixed."""

        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            checkpoint = root / "checkpoint"
            self.assertEqual(self._run("snapshot", paths, checkpoint).returncode, 0)
            originals = [f"newer-{index}\n".encode() for index in range(4)]
            for path, contents in zip(paths, originals, strict=True):
                path.write_bytes(contents)
                path.chmod(0o600)

            fake_bin = root / "fake-bin"
            fake_bin.mkdir(mode=0o700)
            counter = root / "replacement-count"
            fake_mv = fake_bin / "mv"
            fake_mv.write_text(
                "#!/bin/bash\n"
                "set -eu\n"
                "if [[ \"$*\" == *'.airlock-rollback-stage.'* ]]; then\n"
                f"  count_file={counter!s}\n"
                "  count=0\n"
                "  if [ -e \"$count_file\" ]; then count=$(cat \"$count_file\"); fi\n"
                "  count=$((count + 1))\n"
                "  printf '%s\\n' \"$count\" > \"$count_file\"\n"
                "  if [ \"$count\" -eq 2 ]; then exit 75; fi\n"
                "fi\n"
                "exec /usr/bin/mv \"$@\"\n",
                encoding="utf-8",
            )
            fake_mv.chmod(0o700)
            copy = root / "rollback-fault-copy.sh"
            contents = SCRIPT.read_text(encoding="utf-8")
            self.assertIn("export PATH=/usr/bin:/bin", contents)
            copy.write_text(
                contents.replace(
                    "export PATH=/usr/bin:/bin",
                    f"export PATH={fake_bin}:/usr/bin:/bin",
                    1,
                ),
                encoding="utf-8",
            )
            copy.chmod(0o700)

            result = self._run("restore", paths, checkpoint, script=copy)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("attempting recovery", result.stderr)
            self.assertEqual([path.read_bytes() for path in paths], originals)

    def test_refuses_foreign_owned_source_when_testable(self) -> None:
        with self._temporary_root() as temporary:
            root = Path(temporary)
            paths = self._paths(root)
            foreign_uid = 1 if os.geteuid() != 1 else 2
            try:
                os.chown(paths[0], foreign_uid, -1)
            except OSError:
                self.skipTest("test user cannot create a foreign-owned fixture")
            result = self._run("snapshot", paths, root / "checkpoint")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe", result.stderr)

    def test_script_is_directly_executable(self) -> None:
        self.assertEqual(stat.S_IMODE(SCRIPT.stat().st_mode), 0o755)
        direct = subprocess.run([str(SCRIPT)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(direct.returncode, 2)
        self.assertIn("usage:", direct.stderr)


if __name__ == "__main__":
    unittest.main()
