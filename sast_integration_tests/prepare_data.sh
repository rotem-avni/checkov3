#!/bin/bash

pipenv run checkov -s --framework sast_python -d flask --bc-api-key $BC_KEY -o json > checkov_report_sast_python.json
pipenv run checkov -s --framework sast_java -d jenkins --bc-api-key $BC_KEY -o json > checkov_report_sast_java.json
pipenv run checkov -s --framework sast_javascript -d axios --bc-api-key $BC_KEY -o json > checkov_report_sast_javascript.json
