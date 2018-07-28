
# Wrapper for Launching Alert Logic Cloud Insight Environment
This script will register credentials and launch new Cloud Insight environment based on the given scope. Components that will be created:

- New Credentials based on the provided IAM role + external ID
- New Cloud Insight environment based on the given credentials and scope

## Requirements
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (this call is made from Cloud Insight API end point)
* IAM role for Cloud Insight (see https://docs.alertlogic.com/gsg/amazon-web-services-cloud-insight-get-started.htm )
* JSON/CSV file consisting the scope of VPC or regions to protect
* Optional JSON/CSV file consisting the target subnet to deploy Cloud Insight in guided mode

## Cloud Insight Mode
This script support deployment in two mode:
* Automatic = provide only the input scope in `.json` or `.csv` format
* Guided = provide both input and Otis configuration in `.json` or `.csv` format

## Deployment Mode
* DISC = launch Cloud Insight with or without scope, initiate AWS environment discovery
* ADD = update existing Cloud Insight environment with new scope (replace)
* DEL = delete the existing Cloud Insight environment
* APD = append scope to existing environment
* RMV = remove scope from existing environment


## Sample Usage - Discovery
Discovery with scope, replace the parameters to match your environment and run this command ::

	python al_ci_aws_cross_setup.py DISC --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCI --ext My_ext_id --cred TestArgCred --env TestEnv --scope input.json

Discovery only, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py DISC --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCI --ext My_ext_id --cred TestArgCred --env TestEnv

Take note of the output from the script, you will need to record the Environment ID if you wish to delete it later using this script (see below)

## Sample Usage - Discovery + Guided
Guided Discovery with scope, replace the parameters to match your environment and run this command ::

	python al_ci_aws_cross_setup.py DISC --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCI --ext My_ext_id --cred TestArgCred --env TestEnv --scope input.csv --otis otis.csv

## Sample Usage - Add
Add / replace scope of existing environment, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py ADD --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 89C90B43-7C50-4766-8ECD-37F9B9CD150B --scope input.json

Take note of the output from the script, you will need to record the Environment ID if you wish to delete it later using this script (see below).

The input scope will be used as the final scope (replacing the existing scope). If you add new VPC into the scope, then a new Cloud Insight scanner will be launched on the target VPC. If you remove VPC from the scope, then the Cloud Insight scanner on that VPC will be removed.

## Sample Usage - Add + Guided
Add / replace scope of existing environment, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py ADD --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 89C90B43-7C50-4766-8ECD-37F9B9CD150B --scope input.json --otis otis.json

## Sample Usage - Append
Append to existing environment scope, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py APD --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 89C90B43-7C50-4766-8ECD-37F9B9CD150B --scope input.json

Take note of the output from the script, you will need to record the Environment ID if you wish to delete it later using this script (see below).

The input scope will be appened to existing environment. The VPC or region in the existing scope will not be touched / modified.

## Sample Usage - Remove
Remove scope from existing environment, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py RMV --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 89C90B43-7C50-4766-8ECD-37F9B9CD150B --scope input.json

Take note of the output from the script, you will need to record the Environment ID if you wish to delete it later using this script (see below).

VPC or region in the input scope will be removed from the environment. If the final scope is empty, the environment will stay running until you explicitly delete it.

## Sample Usage - Delete
Delete existing environment, replace the parameters to match your environment and run this command ::

    python al_ci_aws_cross_setup.py DEL --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --envid 89C90B43-7C50-4766-8ECD-37F9B9CD150B


## Arguments
Argument | Value | Description
----------- | ----------| -----------
-h, --help | | show this help message and exit
--user | string | User name / email address for API Authentication
--pswd | string | Password for API Authentication
--cid | numeric | Alert Logic Customer CID as target for this deployment
--aws | numeric | Customer AWS Account Number where IAM role is deployed
--arn | string | Cross Account IAM role arn
--ext | numeric | External ID specified in IAM role trust relationship (must equal to CID)
--cred | string | Credential name, free form label, not visible in Alert Logic UI
--env | string | Environment name, will be displayed in Alert Logic UI under Deployment
--scope | `.json` or `.csv` | json/csv formated file with the VPC scope details
--time | numeric | time out in second for this script to run
--filter | | Filter the output to only show the new changes
--skip | | Skip schema validation check
--otis	| `.json or `.csv` | json/csv formated file with the target subnet for Guided mode

The `input.json` or `input.csv` file sample can be found inside this repository, if you use the `.csv` format, the script will automatically reformat it to match the `.json` format. More details about the schema can be found in [here]( https://console.cloudinsight.alertlogic.com/api/sources/#api-JSON_Formats-AWSEnvironmentSourceJSONFormat)

The `otis.json` or `otis.csv` file sample also can be found inside this repository. More details about otis schema can be found in [here](https://console.cloudinsight.alertlogic.com/api/otis/#api-Tuning_Operations_V2-Write_an_option)

Warning: If you skip the schema validation check, the subsequent add / remove / update may error due to missing component in the scope file, use --skip with caution.

## Exit Code
If you going to integrate this script to another orchestration tool, you can use the exit code to detect the status:

* 0 = script run successfully
* 1 = missing or invalid argument
* 2 = environment issue such as invalid environment id, invalid password, or invalid scope
* 3 = timeout

WARNING: This script will not revert back any changes due to timeout, any commands / API calls that it executed prior to timeout will run until completed, even if the script exit due to timeout.

# License and Authors
License:
Distributed under the Apache 2.0 license.

Authors:
Welly Siauw (welly.siauw@alertlogic.com)
