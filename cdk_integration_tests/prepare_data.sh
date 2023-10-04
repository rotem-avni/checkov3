#!/bin/bash

# iterate over all the cdk python checks
for file in "checkov/cdk/checks/python"/*; do
  # Ensure it's a regular file (not a directory or symlink, etc.)
    if [ -f "$file" ]; then
        basename=$(basename -- "$file")
        filename="${basename%.*}"
        # create a report for this check
        echo "creating report for check: $filename"
        pipenv run checkov -s --framework sast_python -o json \
          -d "cdk_integration_tests/src/python/$filename" \
          --external-checks-dir "checkov/cdk/checks/python/$filename.yaml" > "checkov_report_cdk_python_$filename.json"
    fi
done

#todo: iterate over all the cdk typescript checks - when ts supported in sast
