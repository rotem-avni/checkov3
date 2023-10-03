#!/bin/bash

# iterate over all the cdk python checks
for file in "../checkov/cdk/checks/python"/*; do
  # Ensure it's a regular file (not a directory or symlink, etc.)
    if [ -f "$file" ]; then
        basename=$(basename -- "$file")
        filename="${basename%.*}"
        # create a report for this check
        pipenv run checkov -s --framework sast_python -o json \
          -d "cdk_integration_tests/src/python/$filename" \
          --external-checks-dir "checkov/cdk/checks/python/$filename.yaml" > "checkov_sast_report_python_$filename.json"
    fi
done
