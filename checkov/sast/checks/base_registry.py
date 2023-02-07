from __future__ import annotations

import logging
import os
import yaml
from typing import List, Any, Optional, Set
from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.checks.base_check_registry import BaseCheckRegistry
from checkov.sast.consts import SastLanguages
from checkov.common.checks_infra.registry import CHECKS_POSSIBLE_ENDING


class Registry(BaseCheckRegistry):
    def __init__(self, checks_dir: str) -> None:
        super().__init__(report_type=CheckType.SAST)
        self.rules: List[str] = []
        self.checks_dir = checks_dir
        self.logger = logging.getLogger(__name__)

    def extract_entity_details(self, entity: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        # TODO
        return '', '', {}

    def load_rules(self, sast_languages: Optional[Set[SastLanguages]]) -> None:
        if sast_languages:
            self._load_checks_from_dir(self.checks_dir, sast_languages)

    def load_external_rules(self, dir: str, sast_languages: Optional[Set[SastLanguages]]) -> None:
        if sast_languages:
            self._load_checks_from_dir(dir, sast_languages)

    def _load_checks_from_dir(self, directory: str, sast_languages: Set[SastLanguages]) -> None:
        dir = os.path.expanduser(directory)
        self.logger.debug(f'Loading external checks from {dir}')
        checks = set()
        for root, d_names, f_names in os.walk(dir):
            self.logger.debug(f"Searching through {d_names} and {f_names}")
            for file in f_names:
                file_ending = os.path.splitext(file)[1]
                if file_ending not in CHECKS_POSSIBLE_ENDING:
                    continue
                with open(os.path.join(root, file), "r") as f:
                    try:
                        rules = yaml.safe_load(f).get('rules', [])
                    except Exception:
                        logging.warning(f'cant parse rule file {file}')
                        continue
                    for rule in rules:
                        for lang in rule.get('languages', []):
                            if lang in [lan.value for lan in sast_languages]:
                                checks.add(os.path.join(root, file))
                                break
        self.rules += list(checks)