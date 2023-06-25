from __future__ import annotations

import logging
from typing import Dict, Any

from checkov.sast.consts import SemgrepAttribute, CHECKOV_SEVERITY_TO_SEMGREP_SEVERITY


class SastCheckParserV02:
    def parse_raw_check_to_semgrep(self, raw_check: Dict[str, Dict[str, Any]], check_file: str | None = None) -> Dict[str, Any]:
        semgrep_rule: Dict[str, Any] = {}
        if not self._raw_check_is_valid(raw_check):
            logging.error(f'cant parse the following policy: {raw_check}')
        try:
            semgrep_rule = self._parse_rule_metadata(raw_check, check_file, semgrep_rule)
            check_definition = raw_check['definition']
            if raw_check.get('mode', '') == 'taint':
                semgrep_rule['mode'] = 'taint'
                semgrep_rule.update(self._parse_taint_definition(check_definition))
            else:
                semgrep_rule.update(self._parse_definition(check_definition))
        except Exception as e:
            logging.error(f'the policy in file {check_file} is misconfigured so it could not be parsed properly.\n{e}')

        return semgrep_rule

    # todo make common to both parsers
    def _raw_check_is_valid(self, raw_check: Dict[str, Any]) -> bool:
        metadata = raw_check.get('metadata')
        if not metadata:
            raise AttributeError('BQL policy is missing the metadata field')
        if not metadata.get('id'):
            raise AttributeError('BQL policy metadata is missing an id value')
        if not raw_check.get('scope', {}).get('languages'):
            raise AttributeError('BQL policy metadata is missing languages')
        else:
            return True

    # todo make common to both parsers -> make the version parsers a subclass of the sastparser?
    def _parse_rule_metadata(self, bql_policy: Dict[str, Any], check_file: str | None, semgrep_rule: Dict[str, Any]) \
            -> Dict[str, Any]:
        metadata = bql_policy['metadata']
        semgrep_rule[str(SemgrepAttribute.ID)] = metadata['id']
        semgrep_rule[str(SemgrepAttribute.MESSAGE)] = metadata.get('guidelines', '')

        languages = bql_policy['scope']['languages']
        semgrep_rule[str(SemgrepAttribute.LANGUAGES)] = languages
        metadata_obj = {
            'name': metadata['name']
        }
        # add optional metadata fields
        semgrep_rule[str(SemgrepAttribute.SEVERITY)] = CHECKOV_SEVERITY_TO_SEMGREP_SEVERITY[metadata.get('severity', 'MEDIUM')]
        if check_file:
            metadata_obj['check_file'] = check_file
        cwe = metadata.get('cwe')
        if cwe:
            metadata_obj[SemgrepAttribute.CWE.value] = cwe
        owasp = metadata.get('owasp')
        if owasp:
            metadata_obj[SemgrepAttribute.OWASP.value] = owasp
        semgrep_rule['metadata'] = metadata_obj
        return semgrep_rule

    def _parse_definition(self, definition: Dict[str, Any], conf: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if not isinstance(definition, dict):
            raise TypeError(f'bad definition type, got {type(definition)} instead of dict')

        conf: Dict[str, Any] = {'patterns': []}

        if definition.get('patterns'):
            conf['patterns'].extend(self._parse_definition(definition['patterns'])['patterns'])
        for k, v in definition.items():
            if k == 'or':
                ors = []
                for or_cond in v:
                    ors.append(self._parse_definition(or_cond))
                conf['patterns'].append({SemgrepAttribute.PATTERN_EITHER.value: ors})

            elif k == 'and':
                for and_cond in v:
                    conf['patterns'].append(self._parse_definition(and_cond))
            elif k == 'pattern':
                conf['patterns'].append({SemgrepAttribute.PATTERN.value: v.replace('<ANY>', '...')})
            elif k == 'regex':
                conf['patterns'].append({SemgrepAttribute.PATTERN_REGEX.value: v.replace('<ANY>', '...')})
            elif k == 'conditions':
                for condition in v:
                    if condition.get('metavariable'):
                        conf['patterns'].append(self._parse_metavariable_condition(condition))
                    else:
                        for ck, cv in condition.items():
                            conf['patterns'].append(self._parse_single_condition(ck, cv))

        return conf

    def _parse_single_condition(self, key: str, value: str) -> Dict[str, str]:
        value = value.replace('<ANY>', '...')
        if key in ['pattern', 'source', 'sink', 'sanitizer', 'propagator']:
            return {str(SemgrepAttribute.PATTERN.value): value}
        elif key == 'regex':
            return {str(SemgrepAttribute.PATTERN_REGEX.value): value}
        elif key == 'not_pattern':
            return {str(SemgrepAttribute.PATTERN_NOT.value): value}
        elif key == 'not_regex':
            return {str(SemgrepAttribute.PATTERN_NOT_REGEX.value): value}
        elif key == 'within':
            return {str(SemgrepAttribute.PATTERN_INSIDE.value): value}
        elif key == 'not_within':
            return {str(SemgrepAttribute.PATTERN_NOT_INSIDE.value): value}

        return {}

    def _parse_metavariable_condition(self, cond: Dict[str, str]) -> Dict[str, Any]:
        metavar_conf = {}
        cond_type = ''
        for k, v in cond.items():
            metavar_conf[k] = v
            if k == 'pattern' or k == 'patterns':
                cond_type = SemgrepAttribute.METAVARIABLE_PATTERN.value
            elif k == 'regex':
                cond_type = SemgrepAttribute.METAVARIABLE_REGEX.value
            elif k == 'comparison':
                cond_type = SemgrepAttribute.METAVARIABLE_COMPARISON.value

        return {cond_type: metavar_conf}

    def _parse_taint_definition(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        conf: Dict[str, Any] = {
            str(SemgrepAttribute.PATTERN_SOURCES): [],
            str(SemgrepAttribute.PATTERN_SINKS): []
        }
        for k, v in definition.items():
            if k == 'source':
                conf[SemgrepAttribute.PATTERN_SOURCES].append(self._parse_single_condition(k, v))
            elif k == 'sources':
                for source in v:
                    if isinstance(source, str):
                        conf[SemgrepAttribute.PATTERN_SOURCES].append(self._parse_single_condition('source', source))
                    elif isinstance(source, dict):
                        conf[SemgrepAttribute.PATTERN_SOURCES].append(self._parse_definition(source))
            elif k == 'sink':
                conf[SemgrepAttribute.PATTERN_SINKS].append(self._parse_single_condition(k, v))
            elif k == 'sinks':
                for sink in v:
                    if isinstance(sink, str):
                        conf[SemgrepAttribute.PATTERN_SINKS].append(self._parse_single_condition('sink', sink))
                    elif isinstance(sink, dict):
                        conf[SemgrepAttribute.PATTERN_SINKS].append(self._parse_definition(sink))
            elif k == 'sanitizer':
                if SemgrepAttribute.PATTERN_SANITIZERS.value not in conf.keys():
                    conf[str(SemgrepAttribute.PATTERN_SANITIZERS)] = []
                conf[SemgrepAttribute.PATTERN_SANITIZERS].append(self._parse_single_condition(k, v))
            elif k == 'sanitizers':
                if SemgrepAttribute.PATTERN_SANITIZERS.value not in conf.keys():
                    conf[str(SemgrepAttribute.PATTERN_SANITIZERS)] = []
                for sanitizer in v:
                    if isinstance(sanitizer, str):
                        conf[SemgrepAttribute.PATTERN_SANITIZERS].append(self._parse_single_condition('sanitizer', sanitizer))
                    elif isinstance(sanitizer, dict):
                        conf[SemgrepAttribute.PATTERN_SANITIZERS].append(self._parse_definition(sanitizer))
            elif k == 'propagator':
                if SemgrepAttribute.PATTERN_PROPAGATORS.value not in conf.keys():
                    conf[str(SemgrepAttribute.PATTERN_PROPAGATORS)] = []
                conf[SemgrepAttribute.PATTERN_PROPAGATORS].append(self._parse_single_condition(k, v))
            elif k == 'propagators':
                if SemgrepAttribute.PATTERN_PROPAGATORS.value not in conf.keys():
                    conf[str(SemgrepAttribute.PATTERN_PROPAGATORS)] = []
                for propagator in v:
                    if isinstance(propagator, str):
                        conf[SemgrepAttribute.PATTERN_PROPAGATORS].append(self._parse_single_condition('propagator', propagator))
                    elif isinstance(propagator, dict):
                        conf[SemgrepAttribute.PATTERN_PROPAGATORS].append(self._parse_definition(propagator))

        return conf