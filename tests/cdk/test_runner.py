from pathlib import Path

import pytest

from checkov.cdk.runner import CdkRunner
from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.bridgecrew.severities import Severities, BcSeverities
from checkov.runner_filter import RunnerFilter

EXAMPLES_DIR = Path(__file__).parent / "examples"


@pytest.mark.xfail(reason="when enforcement rules is supported, then this should pass", strict=True)
def test_runner_honors_enforcement_rules():
    # given
    test_file = EXAMPLES_DIR / "s3.ts"

    # when
    filter = RunnerFilter(framework=[CheckType.CDK], use_enforcement_rules=True)
    # this is not quite a true test, because the checks don't have severities. However, this shows that the check registry
    # passes the report type properly to RunnerFilter.should_run_check, and we have tests for that method
    filter.enforcement_rule_configs = {CheckType.CDK: Severities[BcSeverities.OFF]}
    report = CdkRunner().run(files=[str(test_file)], runner_filter=filter)

    # then
    summary = report[0].get_summary()

    assert summary["passed"] == 0
    assert summary["failed"] == 0
    assert summary["skipped"] == 0
    assert summary["parsing_errors"] == 0


def test_runner_passing_check():
    # given
    test_file = EXAMPLES_DIR / "s3.ts"

    # when
    report = CdkRunner().run(root_folder="", files=[str(test_file)], runner_filter=RunnerFilter(checks=["CKV_AWS_19"]))

    # then
    summary = report[0].get_summary()

    assert summary["passed"] == 0  # that's a good thing
    assert summary["failed"] == 0
    assert summary["skipped"] == 0
    assert summary["parsing_errors"] == 0


def test_runner_failing_check():
    # given
    test_file = EXAMPLES_DIR / "s3.ts"

    # when
    report = CdkRunner().run(root_folder="", files=[str(test_file)], runner_filter=RunnerFilter(checks=["CKV_AWS_21"]))

    # then
    summary = report[0].get_summary()

    assert summary["passed"] == 0
    assert summary["failed"] == 1
    assert summary["skipped"] == 0
    assert summary["parsing_errors"] == 0
