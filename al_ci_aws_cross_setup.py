# Wrapper for Alert Logic Cloud Insight deployment via API
# Author: welly.siauw@alertlogic.com
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

from __future__ import print_function
import json, requests, datetime, sys, argparse, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import jsonschema
from jsonschema import validate

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API Endpoint
YARP_URL="api.cloudinsight.alertlogic.com"
ALERT_LOGIC_CI_SOURCE = "https://api.cloudinsight.alertlogic.com/sources/v1/"
ALERT_LOGIC_CI_LAUNCHER = "https://api.cloudinsight.alertlogic.com/launcher/v1/"

# Using jsonschema Python library. (http://json-schema.org)
# Schema for scope in Cloud Insight source
schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "Cloud Insight Scope",
    "description": "Schema for CI Scope",
    "type": "object",
    "properties": {        
        "include": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type" : {
                        "type": "string",
                        "enum": [ "vpc", "region", "subnet"]
                    },
                    "key": {
                        "type": "string",
                        "pattern": "^/aws/[^/]+(/[^/]+)*$"
                    }
                },
                "required": ["type", "key"]                
            },
            "minItems": 1,
            "uniqueItems": True
        },
        "exclude": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type" : {
                        "type": "string",
                        "enum": [ "vpc", "region", "subnet"]
                    },
                    "key": {
                        "type": "string",
                        "pattern": "^/aws/[^/]+(/[^/]+)*$"
                    }
                },
                "required": ["type", "key"]
            }
        }
    },
    "required": ["include"]
}

def scope_schema_check(json_data):
	print("Validate the scope using the following schema:")	
	print(json.dumps(schema, indent=4))

	# The data to be validated:
	data =[]
	data.append(json_data)

	print("\nRaw input data:")
	print(json.dumps(data, indent=4))

	print("Validation input data using the schema:")
	for idx, item in enumerate(data):
	    try:
	        validate(item, schema)
	        sys.stdout.write("Record #{}: OK\n".format(idx))
	        return True
	    except jsonschema.exceptions.ValidationError as ve:
	        sys.stderr.write("Record #{}: ERROR\n".format(idx))
	        sys.stderr.write(str(ve) + "\n")
	        return False

def open_input_file(file_path):
	try:
		with open(file_path) as input_data:
			RESULT = json.load(input_data)
			return RESULT
	except IOError:
		print ("### File not found : " + str(file_path) + " - script terminated ###")
		return False

def authenticate(user, paswd, yarp):
	#Authenticate with CI yarp to get token
	url = yarp
	user = user
	password = paswd
	r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=False)
	if r.status_code != 200:
		sys.exit("Unable to authenticate %s" % (r.status_code))
	account_id = json.loads(r.text)['authentication']['user']['account_id']
	token = r.json()['authentication']['token']
	return token

def prep_credentials(iam_arn, iam_ext_id, cred_name):
	#Setup dictionary for credentials payload
	RESULT = {}
	RESULT['credential']  = {}
	RESULT['credential']['name'] = str(cred_name)
	RESULT['credential']['type'] = "iam_role"
	RESULT['credential']['iam_role'] = {}	
	RESULT['credential']['iam_role']['arn'] = str(iam_arn)
	RESULT['credential']['iam_role']['external_id'] = str(iam_ext_id)	
	return RESULT

def post_credentials(token, payload, target_cid):
	#Call API with method POST to create new credentials, return the credential ID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/"
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)	
	print ("Create Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['credential']  = {}
		RESULT['credential']['id'] = "n/a"		
	return RESULT

def prep_ci_source_environment(aws_account, cred_id, environment_name, scope_data):
	#Setup dictionary for environment payload
	RESULT = {}
	RESULT['source']  = {}
	RESULT['source']['config'] = {}
	RESULT['source']['config']['aws'] = {}
	RESULT['source']['config']['aws']['account_id'] = aws_account	
	RESULT['source']['config']['aws']['discover'] = True
	RESULT['source']['config']['aws']['scan'] = True
	RESULT['source']['config']['aws']['credential'] = {}
	RESULT['source']['config']['aws']['credential']['id'] = cred_id

	if (scope_data["include"] or scope_data["exclude"]):
		RESULT['source']['config']['aws']['scope'] = {}	
		RESULT['source']['config']['aws']['scope']['include'] = scope_data["include"]
		RESULT['source']['config']['aws']['scope']['exclude'] = scope_data["exclude"]

	RESULT['source']['config']['collection_method'] = "api"
	RESULT['source']['config']['collection_type'] = "aws"
	RESULT['source']['enabled'] = True
	RESULT['source']['name'] = environment_name
	RESULT['source']['product_type'] = "outcomes"
	RESULT['source']['tags'] = []
	RESULT['source']['type'] = "environment"
	return RESULT

def post_source_environment(token, payload, target_cid):
	#Call API with method POST to create new environment
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/"
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)	
	print ("Create Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))	
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['source'] = {}
		RESULT['source']['id'] = "n/a"
	return RESULT

def put_source_environment(token, payload, target_cid, target_env_id):
	#Call API with method POST to create new environment
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/" + target_env_id	
	REQUEST = requests.put(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)	
	print ("Update Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))	
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['source'] = {}
		RESULT['source']['id'] = "n/a"
	return RESULT

def del_source_environment(token, target_env, target_cid):
	#Delete the specified environment by environment ID and CID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/" + target_env	
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)		
	print ("Delete Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))

def del_source_credentials(token, target_cred, target_cid):
	#Delete the specified credentials by credentials ID and CID
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/" + target_cred	
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)		
	print ("Delete Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	
def get_source_environment(token, target_env, target_cid):
	#Get the source environment detail
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/" + target_env
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)	
	
	print ("Retrieving Environment info status : " + str(REQUEST.status_code), str(REQUEST.reason))	
	if REQUEST.status_code == 200:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['source'] = {}
		RESULT['source']['id'] = "n/a"
	return RESULT

def get_launcher_status(token, target_env, target_cid):
	#Check if Launcher is completed
	API_ENDPOINT = ALERT_LOGIC_CI_LAUNCHER + target_cid + "/environments/" + target_env
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	
	print ("Retrieving Environment launch status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 200:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['scope'] = "n/a"
		
	return RESULT

def get_launcher_data(token, target_env, target_cid):
	#Get all AWS related resource deployed by Cloud Insight
	API_ENDPOINT = ALERT_LOGIC_CI_LAUNCHER + target_cid + "/" + target_env + "/resources"
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	
	print ("Retrieving Environment resources data : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 200:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT['environment_id'] = "n/a"
		
	return RESULT

def launcher_wait_state(token, target_env, target_cid):
	#Wait for launcher to be fully deployed
	print ("\n### Check Launcher Status ###")
	
	while True:
		#Get Launcher Status and check for each region / VPC
		LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)
		if LAUNCHER_RESULT["scope"] != "n/a":
			LAUNCHER_FLAG = True

			for LAUNCHER_REGION in LAUNCHER_RESULT["scope"]:
				print ("Region : " + str(LAUNCHER_REGION["key"])  + " status : " + str(LAUNCHER_REGION["protection_state"]) )
				if LAUNCHER_REGION["protection_state"] != "completed":
					LAUNCHER_FLAG = False
			
			if LAUNCHER_FLAG == True:								
				print ("\n### Launcher Completed Successfully ###")
				LAUNCHER_RETRY = 5

				while LAUNCHER_RETRY > 0:									
					LAUNCHER_DATA = get_launcher_data(token, target_env, target_cid)
					if LAUNCHER_DATA["environment_id"] != "n/a":
						print ("\n### Successfully retrieve Launcher data ###")
						for LAUNCHER_VPC in LAUNCHER_DATA["vpcs"]:
							print ("Region: " + str(LAUNCHER_VPC["region"]))
							print ("VPC: " + str(LAUNCHER_VPC["vpc_key"]))
							print ("SG: " + str(LAUNCHER_VPC["security_group"]["resource_id"]))
							print ("\n")
						LAUNCHER_RETRY = 0
					else:
						print ("\n### Failed to retrieve Launcher Data, see response code + reason above, retrying in 10 seconds ###")
						time.sleep(10)
						LAUNCHER_RETRY = LAUNCHER_RETRY -1

				break

		#Sleep for 10 seconds
		time.sleep(10)

def failback(token, cred_id, target_cid):
	#Failback, delete credentials if create environment failed
	API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/" + cred_id
	REQUEST = requests.delete(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)	
	print ("   Delete Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	print ("   Failback completed")

#MAIN MODULE
if __name__ == '__main__':
	
	#Prepare parser and argument
	parent_parser = argparse.ArgumentParser()
	subparsers = parent_parser.add_subparsers(help="Select mode", dest="mode")
	
	#Add parser for both ADD and DELETE mode
	dis_parser = subparsers.add_parser("DISC", help="Create new environment and discovery")
	add_parser = subparsers.add_parser("ADD", help="Add scope to environment")
	del_parser = subparsers.add_parser("DEL", help="Delete environment")
	
	#Parser argument for Discovery	
	dis_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	dis_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	dis_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for this deployment")
	dis_parser.add_argument("--aws", required=True, help="Customer AWS Account Number where IAM role is deployed")
	dis_parser.add_argument("--arn", required=True, help="Cross Account IAM role arn")
	dis_parser.add_argument("--ext", required=True, help="External ID specified in IAM role trust relationship")
	dis_parser.add_argument("--cred", required=True, help="Credential name, free form label, not visible in Alert Logic UI")
	dis_parser.add_argument("--env", required=True, help="Environment name, will be displayed in Alert Logic UI under Deployment")
	dis_parser.add_argument("--scope", required=False, help="Optional path to JSON file with the region / scope scope detail")

	#Parser argument for Add scope
	add_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	add_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	add_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	add_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	add_parser.add_argument("--scope", required=True, help="Path to JSON file with the region / scope scope detail")

	#Parser argument for Delete environment
	del_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	del_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	del_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for removal")
	del_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for removal")
	
	args = parent_parser.parse_args()
	
	#Set argument to variables
	if args.mode == "DISC":	
		EMAIL_ADDRESS = args.user 
		PASSWORD = args.pswd 
		TARGET_CID = args.cid
		TARGET_AWS_ACCOUNT = args.aws
		TARGET_IAM_ROLE_ARN = args.arn
		TARGET_EXT_ID = args.ext
		TARGET_CRED_NAME = args.cred
		TARGET_ENV_NAME = args.env
		TARGET_SCOPE = args.scope

	elif args.mode == "ADD":
		EMAIL_ADDRESS = args.user
		PASSWORD = args.pswd
		TARGET_CID = args.cid	
		TARGET_ENV_ID = args.envid
		TARGET_SCOPE = args.scope

	elif args.mode == "DEL":
		EMAIL_ADDRESS = args.user
		PASSWORD = args.pswd
		TARGET_CID = args.cid	
		TARGET_ENV_ID = args.envid
	
	if args.mode == "DISC":
		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = Discovery ###\n")	
		
		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))

		#Create credentials using the IAM role ARN and external ID	
		CRED_PAYLOAD = prep_credentials(TARGET_IAM_ROLE_ARN, TARGET_EXT_ID, TARGET_CRED_NAME)		
		CRED_RESULT = post_credentials(TOKEN, str(json.dumps(CRED_PAYLOAD, indent=4)), TARGET_CID)
		CRED_ID = str(CRED_RESULT['credential']['id'])

		if CRED_ID != "n/a":		
			print ("Cred ID : " + CRED_ID)
			
			#Check if scope provided 
			if args.scope:
				#Read scope file	
				print ("### Reading input file ... ###")
				INPUT_SCOPE = []
				INPUT_SCOPE = open_input_file(TARGET_SCOPE)	

				if INPUT_SCOPE != False:
					#Check input file against the json schema to make sure it's valid
					if scope_schema_check(INPUT_SCOPE):
						print ("\n### Schema validation OK - continue to add environment scope ###")
						VALID_SCOPE = True
					else:
						print ("\n### Schema validation issues, please read error message above ###")
						#Prepare empty scope
						INPUT_SCOPE = {}
						INPUT_SCOPE["include"] = []
						INPUT_SCOPE["exclude"] = []
						VALID_SCOPE = False

			else:
				print ("### No scope available ###")
				#Prepare empty scope
				INPUT_SCOPE = {}
				INPUT_SCOPE["include"] = []
				INPUT_SCOPE["exclude"] = []
				VALID_SCOPE = False

			#Create new environment using credentials ID and target AWS Account number
			ENV_PAYLOAD = prep_ci_source_environment(TARGET_AWS_ACCOUNT, CRED_ID, TARGET_ENV_NAME, INPUT_SCOPE)			
			ENV_RESULT = post_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID)
			ENV_ID = str(ENV_RESULT['source']['id'])

			if ENV_ID != "n/a":
				print ("Env ID : " + ENV_ID)
				print ("\n### Cloud Insight Environment created successfully ###")

				#If Scope included, do LAuncher check
				if args.scope and VALID_SCOPE:										
					#Check and wait until launcher completed
					launcher_wait_state(TOKEN, ENV_ID, TARGET_CID)
				else:
					print ("\n### No scope defined, skipping Launcher Status ###")

			else:
				print ("### Failed to create environment source, see response code + reason above, starting fallback .. ###")
				failback(TOKEN, CRED_ID, TARGET_CID)

		else:
			print ("### Failed to create credentials, see response code + reason above, stopping .. ###")
				
	elif args.mode == "ADD":
		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = Add/Update Scope ###\n")	

		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		
		#Read scope file	
		print ("### Reading input file ... ###")
		INPUT_SCOPE = []
		INPUT_SCOPE = open_input_file(TARGET_SCOPE)	

		if INPUT_SCOPE != False:
			#Check input file against the json schema to make sure it's valid
			if scope_schema_check(INPUT_SCOPE):
				print ("\n### Schema validation OK - continue to update environment scope ###")
				
				#Check if the provided Environment ID exist and valid
				SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
				
				if SOURCE_RESULT["source"]["id"] != "n/a":
					
					#Build new payload based on original source + new scope
					ENV_PAYLOAD = SOURCE_RESULT
					del ENV_PAYLOAD["source"]["created"]
					del ENV_PAYLOAD["source"]["modified"]
					ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE
					
					#Update the source environment based on env ID and new payload
					ENV_RESULT = put_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID, TARGET_ENV_ID)
					ENV_ID = str(ENV_RESULT['source']['id'])
										
					if ENV_ID != "n/a":
						print ("   Env ID : " + ENV_ID)
						print ("\n### Cloud Insight Environment updated successfully ###")

						#Check and wait until launcher completed
						launcher_wait_state(TOKEN, ENV_ID, TARGET_CID)
						
					else:
						print ("### Failed to update environment scope, see response code + reason above, starting fallback .. ###")

				else:
					print ("Failed to find the environment ID, see response code + reason above, stopping ..")
			else:
				print ("\n### Schema validation issues, please read error message above ###")
		
	elif args.mode == "DEL":

		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = Delete ###\n")

		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))

		#Check if the provided Environment ID exist and valid
		SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
		
		if SOURCE_RESULT["source"]["id"] != "n/a":
			TARGET_CRED_ID = SOURCE_RESULT["source"]["config"]["aws"]["credential"]["id"]
			print ("Env ID : " + TARGET_ENV_ID)
			print ("Credential ID : " + TARGET_CRED_ID)

			#Delete the environment and credentials associated with that environment
			del_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
			del_source_credentials(TOKEN, TARGET_CRED_ID, TARGET_CID)

		else:
			print ("Failed to find the environment ID, see response code + reason above, stopping ..")

	print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")	
	