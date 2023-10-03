#!/bin/bash

pipenv run checkov -s --framework sast_python -o json \
    -d cdk_integration_tests/src/python/S3BucketEncryption \
    --external-checks-dir checkov/cdk/checks/python/S3BucketEncryption.yaml > checkov_sast_report_S3BucketEncryption.json
