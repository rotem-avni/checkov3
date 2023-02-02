from __future__ import annotations
from dataclasses import dataclass

import logging
import semgrep.output_from_core as core
from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.bridgecrew.severities import get_severity
from checkov.common.models.enums import CheckResult
from checkov.common.output.report import Report
from checkov.runner_filter import RunnerFilter
from checkov.common.output.record import Record
from checkov.sast.checks.registry import registry
from semgrep.semgrep_main import main as run_semgrep
from semgrep.output import OutputSettings, OutputHandler
from semgrep.constants import OutputFormat, RuleSeverity
from semgrep.rule_match import RuleMatchMap
from semgrep.target_manager import FileTargetingLog
from semgrep.profile_manager import ProfileManager
from semgrep.profiling import ProfilingData
from semgrep.parsing_data import ParsingData
from semgrep.error import SemgrepError
from semgrep.rule import Rule

from typing import Collection, List, Set, Dict
from io import StringIO
from pathlib import Path

logger = logging.getLogger(__name__)


SEMGREP_SEVERITY_TO_CHECKOV_SEVERITY = {
    RuleSeverity.ERROR: 'HIGH',
    RuleSeverity.WARNING: 'MEDIUM',
    RuleSeverity.INFO: 'LOW',
}

@dataclass
class SemgrepOutput:
    matches: RuleMatchMap
    errors: List[SemgrepError]
    all_targets: Set[Path]
    renamed_targets: Set[Path]
    target_manager_ignore_log: FileTargetingLog
    filtered_rules: List[Rule]
    profiler: ProfileManager
    profiling_data: ProfilingData
    parsing_data: ParsingData
    explanations: List[core.MatchingExplanation]
    shown_severities: Collection[RuleSeverity]
    target_manager_lockfile_scan_info: Dict[str, int]


class Runner():
    check_type = CheckType.SAST  # noqa: CCE003  # a static attribute

    def run(self, root_folder: str | None, external_checks_dir: list[str] | None = None, files: list[str] | None = None,
            runner_filter: RunnerFilter | None = None, collect_skip_comments: bool = True) -> Report:
        StringIO()
        output_settings = OutputSettings(output_format=OutputFormat.JSON)
        output_handler = OutputHandler(output_settings)
        
        registry.load_checks(runner_filter.sast_languages)
        if external_checks_dir:
            for external_checks in external_checks_dir:
                registry.load_external_checks(external_checks, runner_filter.sast_languages)

        if root_folder:
            targets = [root_folder]
        if files:
            targets = files
        config = registry.checks
        
        semgrep_output = Runner._get_semgrep_output(targets=targets, config=config, output_handler=output_handler)
        report = self._get_report(semgrep_output)
        return report

    @staticmethod
    def _get_semgrep_output(targets: List[str], config: List[str], output_handler: OutputHandler) -> SemgrepOutput:
        (filtered_matches_by_rule,
         semgrep_errors,
         all_targets,
         renamed_targets,
         target_manager_ignore_log,
         filtered_rules,
         profiler,
         profiling_data,
         parsing_data,
         explanations,
         shown_severities,
         target_manager_lockfile_scan_info) = run_semgrep(output_handler=output_handler, target=targets,
                                                          pattern="", lang="", configs=config, **{})
        semgrep_output = SemgrepOutput(filtered_matches_by_rule, semgrep_errors, all_targets, renamed_targets,
                                       target_manager_ignore_log, filtered_rules, profiler, profiling_data,
                                       parsing_data, explanations, shown_severities, target_manager_lockfile_scan_info)
        return semgrep_output

    def _get_report(self, semgrep_output: SemgrepOutput) -> Report:
        report = Report(self.check_type)
        for rule, matches in semgrep_output.matches.items():
            for match in matches:
                check_id = rule.id.split('.')[-1]
                check_name = rule.metadata.get('name', '')
                code_block = Runner._get_code_block(match.lines, match.start.line)
                file_abs_path = match.match.location.path
                file_path = file_abs_path.split('/')[-1]
                severity = get_severity(SEMGREP_SEVERITY_TO_CHECKOV_SEVERITY.get(rule.severity))
                file_line_range = [match.start.line, match.end.line]
                check_result = {'result': CheckResult.FAILED, 'evaluated_keys': {}}

                record = Record(check_id=check_id, check_name=check_name, resource=None, evaluations={},
                                check_class=None, check_result=check_result, code_block=code_block,
                                file_path=file_path, file_line_range=file_line_range,
                                file_abs_path=file_abs_path, severity=severity)
                report.add_record(record)
        return report
    
    @staticmethod
    def _get_code_block(lines, start):
        code_block = []
        index = start
        for line in lines:
            code_block.append((index, line))
            index += 1
        return code_block
