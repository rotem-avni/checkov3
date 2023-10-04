from __future__ import annotations

from collections.abc import Iterable
from typing import Set

from checkov.common.bridgecrew.check_type import CheckType
from checkov.sast.checks_infra.base_registry import Registry
from checkov.sast.consts import SastLanguages


class BaseCdkRegistry(Registry):
    def __init__(self, checks_dir: str) -> None:
        super().__init__(checks_dir=checks_dir)
        self.report_type = CheckType.CDK
