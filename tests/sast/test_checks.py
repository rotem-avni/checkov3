from __future__ import annotations

import os
import pathlib
from pathlib import Path

import pytest

from checkov.sast.runner import Runner
from checkov.sast.checks_infra.registry import registry
from checkov.runner_filter import RunnerFilter
from tests.common.graph.checks.test_yaml_policies_base import load_yaml_data, get_expected_results_by_file_name

BASE_DIR = Path(__file__).parent / 'checks'
CHECK_ID_MAP: "dict[str, str]" = {}  # will be filled via setup()


def test_ChmodPermissiveMask():
    run_check(lang="python", check="ChmodPermissiveMask")


def test_WildcardNeutralizationHandling():
    run_check(lang="python", check="WildcardNeutralizationHandling")


def test_SuperuserPort():
    run_check(lang="python", check="SuperuserPort")


def test_SpecialElementsSQLNeutralization():
    run_check(lang="python", check="SpecialElementsSQLNeutralization")


def test_PubliclyExposedServer():
    run_check(lang="python", check="PubliclyExposedServer")


def test_InputNeutralizationHandling():
    run_check(lang="python", check="InputNeutralizationHandling")


def test_ExecUsage():
    run_check(lang="python", check="ExecUsage")


def test_HardcodedTempDir():
    run_check(lang="python", check="HardcodedTempDir")


def test_HardcodedPassword():
    run_check(lang="python", check="HardcodedPassword")


def test_ExceptionalConditionsHandling():
    run_check(lang="python", check="ExceptionalConditionsHandling")


def test_EncryptionKeySize():
    run_check(lang="python", check="EncryptionKeySize")


def test_HazelcastSymmetricEncryption():
    run_check(lang="java", check="HazelcastSymmetricEncryption")


def test_HttpOnlyCookie():
    run_check(lang="java", check="HttpOnlyCookie")


def test_InadequateAlgorithmStrength():
    run_check(lang="java", check="InadequateAlgorithmStrength")


def test_CrossDomainUntrusted():
    run_check(lang="java", check="CrossDomainUntrusted")


def test_BrokenCryptographicAlgorithm():
    run_check(lang="java", check="BrokenCryptographicAlgorithm")


def test_InadequateKeyStrength():
    run_check(lang="java", check="InadequateKeyStrength")


def test_InsecureCookie():
    run_check(lang="java", check="InsecureCookie")


def test_PersistentCookie():
    run_check(lang="java", check="PersistentCookie")


def test_SensitiveInfoInCookie():
    run_check(lang="java", check="SensitiveInfoInCookie")


def test_TrustBoundary():
    run_check(lang="java", check="TrustBoundary")


def test_DataIntegrityInTransmition():
    run_check(lang="java", check="DataIntegrityInTransmition")


def test_RESTWebServiceSecurity():
    run_check(lang="java", check="RESTWebServiceSecurity")

def test_CreateTempFileInsecurePermissions():
    run_check(lang="javascript", check="CreateTempFileInsecurePermissions", check_failed_test=6)

def test_EncryptionKeySize():
    run_check(lang="javascript", check="EncryptionKeySize", check_failed_test=8)

def test_EncryptUsingSalt():
    run_check(lang="javascript", check="EncryptUsingSalt", check_failed_test=36)

def test_InsecureHttp():
    run_check(lang="javascript", check="InsecureHttp", check_failed_test=4)

def test_InsecureHttpRequest():
    run_check(lang="javascript", check="InsecureHttpRequest", check_failed_test=4)

def test_RsaWithOAEP():
    run_check(lang="javascript", check="RsaWithOAEP", check_failed_test=2)

def test_SuperuserPort():
    run_check(lang="javascript", check="SuperuserPort", check_failed_test=4)

def test_SymmetricEncryption():
    run_check(lang="javascript", check="SymmetricEncryption", check_failed_test=5)

def test_WeakHash():
    run_check(lang="javascript", check="WeakHash", check_failed_test=6)

@pytest.fixture(autouse=True)
def setup():
    global CHECK_ID_MAP
    runner_filter = RunnerFilter(framework=['sast'])
    registry.set_runner_filter(runner_filter=runner_filter)
    registry.load_rules(runner_filter.framework, runner_filter.sast_languages)
    CHECK_ID_MAP = {check['metadata']['check_file'].split('.')[0]: check['id'] for check in registry.rules}


def run_check(lang: str, check: str, check_failed_test: int = 0) -> None:
    # set path where to find test files
    test_dir_path = BASE_DIR / lang / check

    # setup sast runner
    runner = Runner()
    runner.registry.temp_semgrep_rules_path = os.path.join(pathlib.Path(__file__).parent.resolve(),
                                                           f'test_{check}_temp_rules.yaml')

    cur_dir = pathlib.Path(__file__).parent.resolve()
    test_files_dir = os.path.join(cur_dir, 'source_code', lang, check)

    # run actual check
    reports = runner.run(test_files_dir, runner_filter=RunnerFilter(framework=['sast'], checks=CHECK_ID_MAP[check]))

    # get actual results
    assert len(reports) == 1
    report = reports[0]
    summary = report.get_summary()
    if check_failed_test != 0:
        assert summary.get("failed", 0) == check_failed_test

    failed_checks = {check.file_path.lstrip("/") for check in report.failed_checks}

    # get expected results
    expected_to_fail, _ = get_expected_results_by_file_name(test_dir=test_files_dir)

    # check, if results are correct
    assert summary["failed"] == len(expected_to_fail)
    assert summary["passed"] == 0
    assert summary["skipped"] == 0
    assert summary["parsing_errors"] == 0

    assert failed_checks == set(expected_to_fail)
