#!/bin/bash

pipenv run checkov -s --framework sast_python -d repositories/flask --bc-api-key $BC_KEY -o json > checkov_report_sast_python.json
pipenv run checkov -s --framework sast_java -d repositories/jenkins --bc-api-key $BC_KEY -o json > checkov_report_sast_java.json
pipenv run checkov -s --framework sast_javascript -d repositories/axios --bc-api-key $BC_KEY -o json > checkov_report_sast_javascript.json
