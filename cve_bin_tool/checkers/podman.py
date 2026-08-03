# Copyright (C) 2026 DiBussolo, C.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for Podman
https://www.cvedetails.com/version-list/22772/80467/1/Podman-Project-Podman.html
"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PodmanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"podman"]
    VERSION_PATTERNS: list[str] = [
        r"podman-([0-9]+\.[0-9]+\.[0-9]+)",
        r"podman version ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT: list[tuple[str, str]] = [("podman_project", "podman")]
