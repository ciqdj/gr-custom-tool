# Copyright (C) 2026 DoYitNow
# SPDX-License-Identifier: GPL-2.0-only

"""Public repacks must retain a filter registry's canonical recovery bytes."""

from hashlib import sha256
import struct
import unittest
from unittest.mock import patch

from gr4_editor import demo_build, slots, update_policy


class FilterRegistryPolicyTests(unittest.TestCase):
    def setUp(self):
        # A small synthetic RTOS exercises the actual eight instruction
        # transforms and footer readers without distributing firmware bytes.
        self.gate_offset = 64
        self.policy_base = update_policy.GATE_ENTRY - self.gate_offset
        gate = bytearray(update_policy.GATE_BYTES)
        for address, original, *_ in update_policy.COMPARISONS:
            struct.pack_into("<I", gate, address - update_policy.GATE_ENTRY, original)
        base = bytearray(self.gate_offset) + gate
        struct.pack_into("<3I", base, 0, 0x010B0A1B, 0xE3000A1B, 0xE3A0001B)
        self.base = bytes(base)
        self.version_sites = tuple(slots.BASE + offset for offset in (0, 4, 8))
        patches = (
            patch.object(update_policy, "BASE", self.policy_base),
            patch.object(update_policy, "FACTORY_GATE_SHA256", sha256(gate).hexdigest()),
            patch.object(slots, "KNOWN27_SHA", sha256(self.base).hexdigest()),
            patch.object(slots, "VERSION_SITES", self.version_sites),
            patch.object(demo_build, "VERSION_SITES", self.version_sites),
        )
        for current in patches:
            current.start()
            self.addCleanup(current.stop)

    def registry(self, body=None):
        body = self.base if body is None else bytes(body)
        metadata = {
            "schema_version": 2,
            "compiler": "canonical-registry-v2",
            "compiler_base_sha256": slots.KNOWN27_SHA,
            "compiler_base_size": len(self.base),
            "compiler_base_restore": slots._canonical_restore(self.base, body),
            "recipe_filters": [{"id": "synthetic-filter", "name": "Synthetic"}],
        }
        return slots._finish(bytearray(body), metadata)

    @staticmethod
    def body(data):
        footer_size = 16 + struct.unpack_from("<I", data, len(data) - 8)[0]
        return data[:-footer_size]

    def assert_recoverable(self, data):
        self.assertEqual(data[-16:-8], slots.FOOTER_MAGIC)
        self.assertEqual(sum(struct.unpack("<%dI" % (len(data) // 4), data)) & 0xFFFFFFFF, 0)
        metadata = slots._metadata(data)
        self.assertEqual(metadata["body_sha256"], slots._body_sha(self.body(data)))
        self.assertEqual(slots.canonical_base(data), self.base)
        self.assertTrue(slots.supports_image(data))
        self.assertTrue(demo_build.read_registry(data)["demo_read_only"])
        self.assertEqual(metadata["recipe_filters"],
                         [{"id": "synthetic-filter", "name": "Synthetic"}])
        return metadata

    def test_public_policy_adds_each_gate_instruction_to_registry_restore(self):
        source = self.registry()
        self.assert_recoverable(source)
        output, report = demo_build.prepare_update_policy(source, allow_older=True)
        metadata = self.assert_recoverable(output)
        self.assertEqual(report["changed_instruction_count"], len(update_policy.COMPARISONS))
        self.assertEqual(update_policy.inspect_update_policy(output)["policy"], "allow_older")
        restore = {row["offset"]: bytes.fromhex(row["hex"])
                   for row in metadata["compiler_base_restore"]}
        for address, original, relaxed, *_ in update_policy.COMPARISONS:
            offset = address - self.policy_base
            with self.subTest(address=hex(address)):
                self.assertEqual(struct.unpack_from("<I", output, offset)[0], relaxed)
                self.assertEqual(restore[offset], struct.pack("<I", original))
        self.assertEqual(metadata["update_policy"], update_policy.inspect_update_policy(self.body(output)))

    def test_policy_switch_roundtrip_keeps_registry_editable(self):
        source = self.registry()
        enabled, _ = demo_build.prepare_update_policy(source, allow_older=True)
        repeated, report = demo_build.prepare_update_policy(enabled, allow_older=True)
        self.assertEqual(repeated, enabled)
        self.assertEqual(report["changed_instruction_count"], 0)
        disabled, report = demo_build.prepare_update_policy(enabled, allow_older=False)
        metadata = self.assert_recoverable(disabled)
        self.assertEqual(self.body(disabled)[:len(self.base)], self.base)
        self.assertEqual(report["changed_instruction_count"], len(update_policy.COMPARISONS))
        self.assertEqual(update_policy.inspect_update_policy(disabled)["policy"], "factory")
        gate_offsets = {address - self.policy_base for address, *_ in update_policy.COMPARISONS}
        self.assertFalse(gate_offsets.intersection(row["offset"] for row in metadata["compiler_base_restore"]))
        reenabled, _ = demo_build.prepare_update_policy(disabled, allow_older=True)
        self.assert_recoverable(reenabled)
        self.assertEqual(self.body(reenabled)[:len(self.base)], self.body(enabled)[:len(self.base)])

    def test_unknown_gate_preserves_complete_recoverable_registry(self):
        body = bytearray(self.base)
        body[self.gate_offset + 4] = 1
        source = self.registry(body)
        self.assert_recoverable(source)
        self.assertEqual(update_policy.inspect_update_policy(source)["status"], "unsupported")
        with patch.object(slots, "prepare_update_policy", side_effect=AssertionError("unknown gate delegated")):
            for requested in (True, False):
                with self.subTest(allow_older=requested):
                    output, report = demo_build.prepare_update_policy(source, allow_older=requested)
                    self.assertEqual(output, source)
                    self.assertEqual(self.body(output), body)
                    self.assertTrue(report["preserved_unrecognized"])
                    self.assertEqual(report["changed_instruction_count"], 0)
                    self.assert_recoverable(output)


if __name__ == "__main__":
    unittest.main()
