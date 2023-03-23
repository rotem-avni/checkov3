import ctypes
import json
from os import path
from typing import Dict, Any

current_dir = path.dirname(path.realpath(__file__))
library = ctypes.cdll.LoadLibrary(path.join(current_dir, '../sast_core/library.so'))
analyze_code = library.analyzeCode
analyze_code.restype = ctypes.c_void_p


def run_go_library(source_code_dir: str = '',
                   policy_dir: str = '',
                   language: str = '') -> Dict[str, Any]:
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
    print(entire_file_output, entire_file_bytes, entire_file_string)
    return json.loads(entire_file_string)


# result = run_go_library()
# print(result)