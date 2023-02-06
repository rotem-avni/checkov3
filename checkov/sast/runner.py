from __future__ import annotations

import logging
from dataclasses import dataclass
from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.bridgecrew.severities import get_severity
from checkov.common.models.enums import CheckResult
from checkov.common.output.report import Report
from checkov.common.typing import _CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.common.output.record import Record
from checkov.sast.checks.registry import registry
from checkov.sast.enums import SastLanguages
from semgrep.semgrep_main import main as run_semgrep
from semgrep.output import OutputSettings, OutputHandler
from semgrep.constants import OutputFormat, RuleSeverity, EngineType, DEFAULT_TIMEOUT
from semgrep.core_runner import StreamingSemgrepCore, SemgrepCore, CoreRunner
from typing import Collection, List, Set, Dict, Tuple, Optional, Any, TYPE_CHECKING
from io import StringIO
from pathlib import Path


if TYPE_CHECKING:
    from semgrep.rule_match import RuleMatchMap, RuleMatch
    from semgrep.target_manager import FileTargetingLog
    from semgrep.profile_manager import ProfileManager
    from semgrep.output_extra import OutputExtra
    from semgrep.error import SemgrepError
    from semgrep.rule import Rule


logger = logging.getLogger(__name__)


SEMGREP_SEVERITY_TO_CHECKOV_SEVERITY = {
    RuleSeverity.ERROR: 'HIGH',
    RuleSeverity.WARNING: 'MEDIUM',
    RuleSeverity.INFO: 'LOW',
}

SUPPORT_FILE_EXT = ['py', 'java', 'js']


@dataclass
class SemgrepOutput:
    matches: RuleMatchMap
    errors: List[SemgrepError]
    renamed_targets: Set[Path]
    target_manager_ignore_log: FileTargetingLog
    filtered_rules: List[Rule]
    profiler: ProfileManager
    outputExtra: OutputExtra
    shown_severities: Collection[RuleSeverity]
    target_manager_lockfile_scan_info: Dict[str, int]


class Runner():
    check_type = CheckType.SAST  # noqa: CCE003  # a static attribute

    def should_scan_file(self, file: str) -> bool:
        for ext in SUPPORT_FILE_EXT:
            if file.endswith(ext):
                return True
        return False

    def run(self, root_folder: Optional[str], external_checks_dir: Optional[List[str]] = None, files: Optional[List[str]] = None,
            runner_filter: Optional[RunnerFilter] = None, collect_skip_comments: bool = True) -> Report:
        if not runner_filter:
            logger.warning('no runner filter')
            return Report(self.check_type)

        StringIO()
        output_settings = OutputSettings(output_format=OutputFormat.JSON)
        output_handler = OutputHandler(output_settings)

        registry.load_rules(runner_filter.sast_languages)
        if external_checks_dir:
            for external_checks in external_checks_dir:
                registry.load_external_rules(external_checks, runner_filter.sast_languages)

        if root_folder:
            targets = [root_folder]
        if files:
            targets = files
        config = registry.rules
        if not config:
            logger.warning('no valid checks')
            return Report(self.check_type)

        semgrep_output = Runner._get_semgrep_output(targets=targets, config=config, output_handler=output_handler)
        report = self._create_report(semgrep_output.matches)
        return report

    @staticmethod
    def _get_semgrep_output(targets: List[str], config: List[str], output_handler: OutputHandler) -> SemgrepOutput:
        (filtered_matches_by_rule,
         semgrep_errors,
         renamed_targets,
         target_manager_ignore_log,
         filtered_rules,
         profiler,
         output_extra,
         shown_severities,
         target_manager_lockfile_scan_info) = run_semgrep(output_handler=output_handler, target=targets,
                                                          pattern="", lang="", configs=config, **{})
        semgrep_output = SemgrepOutput(filtered_matches_by_rule, semgrep_errors, renamed_targets,
                                       target_manager_ignore_log, filtered_rules, profiler,
                                       output_extra, shown_severities, target_manager_lockfile_scan_info)
        return semgrep_output

    def _create_report(self, filtered_matches_by_rule: Dict[Rule, List[RuleMatch]]) -> Report:
        report = Report(self.check_type)
        for rule, matches in filtered_matches_by_rule.items():
            for match in matches:
                check_id = rule.id.split('.')[-1]
                check_name = rule.metadata.get('name', '')
                code_block = Runner._get_code_block(match.lines, match.start.line)
                file_abs_path = match.match.location.path
                file_path = file_abs_path.split('/')[-1]
                severity = get_severity(SEMGREP_SEVERITY_TO_CHECKOV_SEVERITY.get(rule.severity))
                file_line_range = [match.start.line, match.end.line]
                check_result = _CheckResult(result=CheckResult.FAILED)

                record = Record(check_id=check_id, check_name=check_name, resource="", evaluations={},
                                check_class="", check_result=check_result, code_block=code_block,
                                file_path=file_path, file_line_range=file_line_range,
                                file_abs_path=file_abs_path, severity=severity)
                report.add_record(record)
        return report

    @staticmethod
    def _get_code_block(lines: List[str], start: int) -> List[Tuple[int, str]]:
        code_block = []
        index = start
        for line in lines:
            code_block.append((index, line))
            index += 1
        return Runner._cut_code_block_ident(code_block)

    @staticmethod
    def _cut_code_block_ident(code_block: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
        min_ident = len(code_block[0][1]) - len(code_block[0][1].lstrip())
        for item in code_block[1:]:
            current_min_ident = len(item[1]) - len(item[1].lstrip())
            if current_min_ident < min_ident:
                min_ident = current_min_ident

        if min_ident == 0:
            return code_block

        code_block_cut_ident = []
        for item in code_block:
            code_block_cut_ident.append((item[0], item[1][min_ident:]))
        return code_block_cut_ident

    @staticmethod
    def _get_generic_ast(language: SastLanguages, target: str) -> Dict[str, Any]:
        try:
            core_runner = CoreRunner(jobs=None, engine=EngineType.OSS, timeout=DEFAULT_TIMEOUT, max_memory=0,
                                     interfile_timeout=0, timeout_threshold=0, optimizations="none", core_opts_str=None)
            cmd = [SemgrepCore.path()] + ['-json', '-full_token_info', '-dump_ast', target, '-lang', language.value]
            runner = StreamingSemgrepCore(cmd, 1)
            runner.vfs_map = {}
            returncode = runner.execute()
            output_json: Dict[str, Any] = core_runner._extract_core_output([], returncode, " ".join(cmd), runner.stdout, runner.stderr)
            return output_json
        except Exception as e:
            logger.error(f'Cant parse AST for this file: {target}, for {language.value}: {str(e)}')
        return {}
