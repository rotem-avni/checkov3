from typing import Dict, Union, List

from checkov.common.output.report import Report
from checkov.sast.consts import POLICIES_ERRORS, POLICIES_ERRORS_COUNT


class SastReport(Report):

    def __init__(self, check_type: str, metadata: Dict[str, Union[str, int, List[str]]], engine_name: str):
        super().__init__(check_type)
        self.metadata = metadata
        self.engine_name = engine_name

    def get_summary(self) -> Dict[str, Union[int, str]]:
        base_summary = super().get_summary()
        base_summary["engine_name"] = str(self.engine_name)

        err_str = ""
        policies_errors: Union[int, str, List[str]] = self.metadata.get(POLICIES_ERRORS, [])
        if policies_errors:
            for e in policies_errors:
                err_str += f"\t- {e}\n"
        base_summary[POLICIES_ERRORS] = err_str
        base_summary[POLICIES_ERRORS_COUNT] = len(policies_errors)
        base_summary = {**base_summary, **{k: v for k, v in self.metadata.items() if k != POLICIES_ERRORS}}

        return base_summary
