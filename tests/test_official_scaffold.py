# Copyright (C) 2026 DoYitNow
# SPDX-License-Identifier: GPL-2.0-only

"""Official filter initialization without private firmware or ARM tooling."""
import struct
import unittest
from unittest.mock import Mock, patch as mock_patch

from gr4_editor import slots
from gr4_editor.official_scaffold import initialize_scaffold


MENU_ENTRIES = (
    0x53912CF4, 0x533CC6E0, 0x53373BC0, 0x53373F84,
    0x53374118, 0x539113FC, 0x5375F0B0, 0x53370738,
)
PERSIST_ENTRIES = (0x533E1C04, 0x533E17CC)
SCALAR_ENTRIES = slots.GETTERS + slots.SETTERS + slots.DEFAULT_ENTRIES


class OfficialScaffoldTests(unittest.TestCase):
    def setUp(self):
        table_sites = tuple(site for _, *sites in slots.TABLES for site in sites)
        sites = SCALAR_ENTRIES + MENU_ENTRIES + PERSIST_ENTRIES + table_sites
        self.patch = slots._Patch(bytes(max(sites) + 4 - slots.BASE))

        def write(site, value):
            struct.pack_into('<I', self.patch.image, site - slots.BASE, value)

        for index, site in enumerate(SCALAR_ENTRIES + MENU_ENTRIES):
            # Distinct native PUSH instructions, with no preexisting branch.
            write(site, 0xE92D4000 | (index + 1))
        for site in PERSIST_ENTRIES:
            write(site, 0xE1A0C00D)

        self.native_rows = {}
        table_bytes = {}
        for index, (family, stride, low, high) in enumerate(slots.TABLES):
            address = 0x55000000 + index * 0x1000
            rows = [[0x56000000 + index * 0x100000 + hardware * 0x10000 + column * 4
                     for column in range(34)] for hardware in range(3)]
            self.native_rows[family] = rows
            table_bytes[address] = struct.pack('<102I', *(value for row in rows for value in row))
            write(stride, 0xE3A02022)
            write(low, slots._mov(3, address & 65535))
            write(high, slots._mov(3, address >> 16, high=True))
        self.original_words = {site: self.patch.word(site) for site in sites}

        def read_table(address, size):
            data = table_bytes[address]
            self.assertEqual(size, len(data))
            return data

        memory = Mock()
        memory.read.side_effect = read_table
        self.memory = memory
        memory_patch = mock_patch('gr4_editor.firmware._Memory', return_value=memory)
        memory_patch.start()
        self.addCleanup(memory_patch.stop)
        catalog_patch = mock_patch('gr4_editor.official_catalogs.initialize_catalogs',
                                   return_value={'source': 'synthetic native catalogs'})
        self.catalogs = catalog_patch.start()
        self.addCleanup(catalog_patch.stop)

    def assert_native_continuation(self, site):
        continuation = slots._target(site, self.patch.word(site))
        self.assertEqual(continuation % 16, 0)
        self.assertEqual(self.patch.word(continuation), self.original_words[site])
        self.assertEqual(slots._target(continuation + 4, self.patch.word(continuation + 4)),
                         site + 4)
        return continuation

    def test_filter_entries_preserve_native_instructions_and_support_scalar_fallbacks(self):
        report = initialize_scaffold(self.patch, filter_registry=True)
        expected = {}
        for site in SCALAR_ENTRIES + MENU_ENTRIES:
            with self.subTest(site=hex(site)):
                expected[site] = self.assert_native_continuation(site)
        reported = {int(row['site'], 16): int(row['continuation'], 16)
                    for row in report['continuations']}
        self.assertEqual(reported, expected)

        # This is the first downstream consumer that used to raise
        # "共享入口不是已知 ARM 分支" on the unprepared official entries.
        fallbacks = slots._restore_scalar_fallbacks(self.patch)
        self.assertEqual({int(row['site'], 16): int(row['native_fallback'], 16)
                          for row in fallbacks},
                         {site: expected[site] for site in SCALAR_ENTRIES})
        for site in SCALAR_ENTRIES:
            self.assert_native_continuation(site)

    def test_filter_directories_keep_each_hardware_row_and_seed_new_columns_from_standard(self):
        report = initialize_scaffold(self.patch, filter_registry=True)
        self.assertEqual(report['native_profile_columns'], 34)
        self.assertEqual(self.memory.read.call_count, len(slots.TABLES))
        for family, stride, low, high in slots.TABLES:
            with self.subTest(family=family):
                self.assertEqual(self.patch.word(stride), 0xE3A02025)
                address = (slots._half(self.patch.word(low)) |
                           slots._half(self.patch.word(high)) << 16)
                self.assertEqual(address % 16, 0)
                expanded = struct.unpack_from('<111I', self.patch.image, address - slots.BASE)
                for hardware, native in enumerate(self.native_rows[family]):
                    row = expanded[hardware * 37:(hardware + 1) * 37]
                    self.assertEqual(row[:34], tuple(native))
                    self.assertEqual(row[34:], (native[11],) * 3)

    def test_default_demo_path_preserves_filter_directories_and_entries(self):
        report = initialize_scaffold(self.patch)
        self.catalogs.assert_called_once_with(self.patch)
        self.memory.read.assert_not_called()
        filter_sites = SCALAR_ENTRIES + MENU_ENTRIES
        filter_sites += tuple(site for _, *sites in slots.TABLES for site in sites)
        for site in filter_sites:
            with self.subTest(site=hex(site)):
                self.assertEqual(self.patch.word(site), self.original_words[site])
        for site in PERSIST_ENTRIES:
            self.assert_native_continuation(site)
        self.assertEqual({int(row['site'], 16) for row in report['continuations']},
                         set(PERSIST_ENTRIES))


if __name__ == '__main__':
    unittest.main()
