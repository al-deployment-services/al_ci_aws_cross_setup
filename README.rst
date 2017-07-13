Wrapper for Launching Alert Logic Cloud Insight Environment
=================
This script will register credentials and launch new Cloud Insight environment based on the given scope. Components that will be created:

- New Credentials based on the provided IAM role + external ID 
- New Cloud Insight environment based on the given credentials and scope 

Requirements
------------
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (this call is made from Cloud Insight API end point)
* IAM role for Cloud Insight (see https://docs.alertlogic.com/gsg/amazon-web-services-cloud-insight-get-started.htm )
* JSON file consisting the scope of VPC or regions to protect

Sample usage
----------

`python al_ci_aws_cross_setup.py --user first.last@company.com --pswd MyCloudInsightPassword --cid 10000 --aws 052672429986 --arn arn:aws:iam::052672429986:role/AlertLogicCrossAccountCI --ext My_ext_id --cred TestArgCred --env TestEnv --scope input.json`

The input.json file sample can be found inside this repository

Arguments
----------
  -h, --help   show this help message and exit
  --user USER  User name / email address for API Authentication
  --pswd PSWD  Password for API Authentication
  --cid CID    Alert Logic Customer CID as target for this deployment
  --aws AWS    Customer AWS Account Number where IAM role is deployed
  --arn ARN    Cross Account IAM role arn
  --ext EXT    External ID specified in IAM role trust relationship
  --cred CRED  Credential name, free form label, not visible in Alert Logic UI
  --env ENV    Environment name, will be displayed in Alert Logic UI under Deployment
  --scope      json formated file with the VPC scope details

License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors: 
Welly Siauw (welly.siauw@alertlogic.com)
