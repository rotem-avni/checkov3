import ctypes
import json
from os import path
from typing import Dict, Any

AVAILABLE_LANGUAGES = {'python'}

current_dir = path.dirname(path.realpath(__file__))
library = ctypes.cdll.LoadLibrary(path.join(current_dir, '../sast_core/library.so'))
analyze_code = library.analyzeCode
analyze_code.restype = ctypes.c_void_p


def run_go_library(source_code_file: str,
                   source_code_dir: str,
                   policy_file: str,
                   policy_dir: str,
                   language: str) -> Dict[str, Any]:
    validate_params(**locals())
    document = {
        "source_code_dir": source_code_dir,
        "source_code_file": source_code_file,
        "policy_dir": policy_dir,
        "policy_file": policy_file,
        "language": language,
    }
    # send the document as a byte array of json format
    entire_file_output = analyze_code(json.dumps(document).encode('utf-8'))

    # we dereference the pointer to a byte array
    entire_file_bytes = ctypes.string_at(entire_file_output)

    # convert our byte array to a string
    entire_file_string = entire_file_bytes.decode('utf-8')
    return json.loads(entire_file_string)


def validate_params(source_code_file: str,
                    source_code_dir: str,
                    policy_file: str,
                    policy_dir: str,
                    language: str):
    if not source_code_file and not source_code_dir:
        raise Exception('must provide source code file or dir for sast runner')
    if not policy_dir and not policy_file:
        raise Exception('must provide policy file or dir for sast runner')
    if not language:
        raise Exception('must provide a language for sast runner')
    if language not in AVAILABLE_LANGUAGES:
        raise Exception(f'currently only support {AVAILABLE_LANGUAGES}')
