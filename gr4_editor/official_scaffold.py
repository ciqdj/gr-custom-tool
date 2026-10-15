# Copyright (C) 2026 DoYitNow
# SPDX-License-Identifier: GPL-2.0-only

"""Prepare the official input for the selected native feature compiler."""

import struct


def initialize_scaffold(patch, *, filter_registry=False):
    from .demo_build import _branch
    from .official_catalogs import initialize_catalogs

    if filter_registry:
        from .slots import TABLES, GETTERS, SETTERS, DEFAULT_ENTRIES, _half, _mov
        from .firmware import _Memory

        # The registry compiler expects expanded profile directories and
        # branch continuations at its shared scalar/menu entries.  The demo
        # crop/End Screen compiler only needs its persistence continuations.
        memory = _Memory(bytes(patch.image))
        tables = {}
        for family, stride, low, high in TABLES:
            address = _half(patch.word(low)) | _half(patch.word(high)) << 16
            native = struct.unpack("<102I", memory.read(address, 408))
            rows = []
            for hardware in range(3):
                original = list(native[hardware * 34:(hardware + 1) * 34])
                rows.extend(original + [original[11]] * 3)
            tables[family] = rows

    catalogs = initialize_catalogs(patch)
    if filter_registry:
        for family, stride, low, high in TABLES:
            address = patch.append(struct.pack("<111I", *tables[family]), 16)
            patch.set_word(stride, 0xE3A02025, "prepare native profile directory")
            patch.set_word(low, _mov(3, address & 65535), "prepare native profile low")
            patch.set_word(high, _mov(3, address >> 16, high=True), "prepare native profile high")
        sites = (*GETTERS, *SETTERS, *DEFAULT_ENTRIES,
                 0x53912CF4, 0x533CC6E0, 0x53373BC0, 0x53373F84, 0x53374118,
                 0x539113FC, 0x5375F0B0, 0x53370738)
    else:
        sites = (0x533E1C04, 0x533E17CC)

    continuations = []
    for site in sites:
        instruction = patch.word(site)
        if not filter_registry and instruction != 0xE1A0C00D:
            raise ValueError("官方设置保存/加载入口与适配布局不一致")
        address = patch.append(lambda at, site=site, instruction=instruction:
                               [instruction, _branch(at + 4, site + 4)], 16)
        patch.set_word(site, _branch(site, address),
                       "preserve original native continuation" if filter_registry else
                       "preserve native persistence continuation")
        continuations.append({"site": hex(site), "continuation": hex(address)})
    report = {"base": "official-1.11.10.7", "catalogs": catalogs,
              "continuations": continuations,
              "resources": "read from the user's input"}
    if filter_registry:
        report["native_profile_columns"] = 34
    return report
