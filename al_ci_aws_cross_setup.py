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
		print ("### File not found : " + str(file_path) + " - scope will be skipped ###")
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

def launcher_wait_state(token, target_env, target_cid,mode):
	#Wait for launcher to be fully deployed
	print ("\n### Check Launcher Status ###")
	
	while True:
		if mode == "ADD" or mode == "DISC" or mode =="APD" or mode =="RMV":			
			#Get Launcher Status and check for each region / VPC
			LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)
			if LAUNCHER_RESULT["scope"] != "n/a":
				LAUNCHER_FLAG = True

				for LAUNCHER_REGION in LAUNCHER_RESULT["scope"]:
					print ("Region : " + str(LAUNCHER_REGION["key"])  + " status : " + str(LAUNCHER_REGION["protection_state"]) )
					if LAUNCHER_REGION["protection_state"] != "completed" and LAUNCHER_REGION["protection_state"] != "removed":
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

		elif mode == "DEL":
			#Get Launcher Status 
			LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)

			if LAUNCHER_RESULT["scope"] == "n/a":
				print ("\n### Launcher Deleted Successfully ###")
				break;

		#Sleep for 10 seconds
		time.sleep(10)

def change_scope_to_list(input_scope, scope_type):
	temp_list = []

	for item in input_scope:
		if item["type"] == scope_type:
			temp_list.append(item["key"])

	return temp_list

def append_scope(source_scope, new_scope, scope_limit):

	#transform Dictionary to List
	original_vpc_scope = change_scope_to_list(source_scope, "vpc")
	new_vpc_scope = change_scope_to_list(new_scope, "vpc")

	#build set for VPC scope by combining existing and new VPC
	final_vpc_scope = original_vpc_scope + new_vpc_scope
	final_vpc_scope = set(final_vpc_scope)

	#transform Dictionary to List
	original_region_scope = change_scope_to_list(source_scope, "region")
	new_region_scope = change_scope_to_list(new_scope, "region")
	
	#build set for Region scope by combining existing and new region
	final_region_scope = original_region_scope + new_region_scope
	final_region_scope = set(final_region_scope)

	#Rebuild the scope to match the schema
	rebuild_scope = {}
	rebuild_scope[scope_limit] = []

	#add all unique vpc
	for item in final_vpc_scope:
		new_item = {}
		new_item["type"] = "vpc"
		new_item["key"] = item
		rebuild_scope[scope_limit].append(new_item)

	#add all unique regions
	for item in final_region_scope:
		new_item = {}
		new_item["type"] = "region"
		new_item["key"] = item
		rebuild_scope[scope_limit].append(new_item)
	
	return rebuild_scope

def remove_scope(source_scope, new_scope, scope_limit):

	#transform Dictionary to List
	original_vpc_scope = change_scope_to_list(source_scope, "vpc")
	new_vpc_scope = change_scope_to_list(new_scope, "vpc")
	
	#transform to Set to make it easier to subtract
	original_vpc_scope = set(original_vpc_scope)
	new_vpc_scope = set(new_vpc_scope)
	
	#substract the scope that will be removed
	final_vpc_scope = original_vpc_scope - new_vpc_scope
	
	#transform Dictionary to List
	original_region_scope = change_scope_to_list(source_scope, "region")
	new_region_scope = change_scope_to_list(new_scope, "region")

	#transform to Set to make it easier to subtract
	original_region_scope = set(original_region_scope)
	new_region_scope = set(new_region_scope)
	
	#substract the scope that will be removed
	final_region_scope = original_region_scope - new_region_scope
	
	#Rebuild the scope to match the schema
	rebuild_scope = {}
	rebuild_scope[scope_limit] = []

	#add all unique vpc
	for item in final_vpc_scope:
		new_item = {}
		new_item["type"] = "vpc"
		new_item["key"] = item
		rebuild_scope[scope_limit].append(new_item)

	#add all unique regions
	for item in final_region_scope:
		new_item = {}
		new_item["type"] = "region"
		new_item["key"] = item
		rebuild_scope[scope_limit].append(new_item)
	
	return rebuild_scope

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
	add_parser = subparsers.add_parser("ADD", help="Add or replace environment scope")
	del_parser = subparsers.add_parser("DEL", help="Delete environment")
	apd_parser = subparsers.add_parser("APD", help="Append scope to environment")
	rmv_parser = subparsers.add_parser("RMV", help="Remove scope to environment")
	
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

	#Parser argument for Append scope
	apd_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	apd_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	apd_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	apd_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	apd_parser.add_argument("--scope", required=True, help="Path to JSON file with the region / scope scope detail")

	#Parser argument for Remove scope
	rmv_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	rmv_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	rmv_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	rmv_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	rmv_parser.add_argument("--scope", required=True, help="Path to JSON file with the region / scope scope detail")
	
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

	elif args.mode == "ADD" or args.mode == "APD" or args.mode == "RMV":
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
	
	if args.mode =="DISC" or args.mode == "ADD" or args.mode =="APD" or args.mode =="RMV":
		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = " + str(args.mode) + " ###\n")

		#Authenticate with Cloud Insight and retrieve token	
		TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		
		#Check if scope provided 
		VALID_SCOPE = True
		if args.scope:
			#Read scope file	
			print ("### Reading input file ... ###")
			INPUT_SCOPE = []
			INPUT_SCOPE = open_input_file(TARGET_SCOPE)

			if INPUT_SCOPE != False:
				#Check input file against the json schema to make sure it's valid
				if scope_schema_check(INPUT_SCOPE):
					print ("\n### Schema validation OK - continue to add / update / remove the environment scope ###")
					VALID_SCOPE = True

				else:
					print ("\n### Schema validation issues, please read error message above ###")
					VALID_SCOPE = False

			else:
				#Cannot find or open the scope file
				VALID_SCOPE = False

		else:
			print ("### No scope included ###")			
			VALID_SCOPE = False

		#Handling missing scope
		if VALID_SCOPE == False and args.mode == "DISC":
			print ("\n### Deployment will continue with empty scope ###")

			#Prepare empty scope for discovery
			INPUT_SCOPE = {}
			INPUT_SCOPE["include"] = []
			INPUT_SCOPE["exclude"] = []
			VALID_SCOPE = True

		elif VALID_SCOPE == False:
			print ("\n### Cannot continue deployment without valid scope ###")

		#Check pre-requisite
		VALID_PREREQ = True		
		if VALID_SCOPE == True:

			#Discovery mode will require new credentials before we can proceed
			if args.mode == "DISC":
				#Create credentials using the IAM role ARN and external ID	
				CRED_PAYLOAD = prep_credentials(TARGET_IAM_ROLE_ARN, TARGET_EXT_ID, TARGET_CRED_NAME)		
				CRED_RESULT = post_credentials(TOKEN, str(json.dumps(CRED_PAYLOAD, indent=4)), TARGET_CID)
				CRED_ID = str(CRED_RESULT['credential']['id'])

				if CRED_ID != "n/a":		
					print ("Cred ID : " + CRED_ID)
					VALID_PREREQ = True
				else:
					print ("### Failed to create credentials, see response code + reason above ###")
					VALID_PREREQ = False
		
		else:			
			VALID_PREREQ = False

		#Deploy if Pre-requisite has been completed
		if VALID_PREREQ == True:
			
			if args.mode == "DISC":
				#Create new environment using credentials ID and target AWS Account number
				#use the input file as the scope
				ENV_PAYLOAD = prep_ci_source_environment(TARGET_AWS_ACCOUNT, CRED_ID, TARGET_ENV_NAME, INPUT_SCOPE)

				#Create new environment to kick discovery
				ENV_RESULT = post_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID)
				ENV_ID = str(ENV_RESULT['source']['id'])

			elif args.mode == "ADD" or args.mode == "APD" or args.mode =="RMV":

				#Check if the provided Environment ID exist and valid
				SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)
				
				if SOURCE_RESULT["source"]["id"] != "n/a":
					
					#Build new payload based on original source + new scope
					ENV_PAYLOAD = SOURCE_RESULT

					#clean up fiedls that is not required
					if ENV_PAYLOAD["source"].has_key("created"): del ENV_PAYLOAD["source"]["created"]
					if ENV_PAYLOAD["source"].has_key("modified"): del ENV_PAYLOAD["source"]["modified"]

					#For Add mode, just use the input scope to replace existing scope
					if args.mode =="ADD":
						ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE

					#For Append mode, add the new scope to the existing scope
					#For Remove mode, subtract the new scope from existing scope
					elif args.mode =="APD" or args.mode == "RMV":
						#Check if the existing environment has scope included
						if SOURCE_RESULT["source"]["config"]["aws"].has_key("scope"):
							
							if args.mode =="APD":
								#rebuild the included scope by appending original + new scope and find all unique regions and vpcs
								REBUILD_INCLUDE_SCOPE = append_scope(SOURCE_RESULT["source"]["config"]["aws"]["scope"]["include"], INPUT_SCOPE["include"], "include")

								#rebuild the excluded scope by appending original + new scope and find all unique regions and vpcs
								REBUILD_EXCLUDE_SCOPE = append_scope(SOURCE_RESULT["source"]["config"]["aws"]["scope"]["exclude"], INPUT_SCOPE["exclude"], "exclude")
							
							elif args.mode == "RMV":
								#rebuild the included scope by subtract original with new scope and find all unique regions and vpcs
								REBUILD_INCLUDE_SCOPE = remove_scope(SOURCE_RESULT["source"]["config"]["aws"]["scope"]["include"], INPUT_SCOPE["include"], "include")

								#rebuild the excluded scope by subtract original with new scope and find all unique regions and vpcs
								REBUILD_EXCLUDE_SCOPE = remove_scope(SOURCE_RESULT["source"]["config"]["aws"]["scope"]["exclude"], INPUT_SCOPE["exclude"], "exclude")

							print ("\nOriginal Scope:")						
							print (json.dumps(SOURCE_RESULT["source"]["config"]["aws"]["scope"], indent=4))
							
							#merge both include and excluded scope and prepare the new payload
							REBUILD_FINAL_SCOPE = {}
							REBUILD_FINAL_SCOPE.update(REBUILD_INCLUDE_SCOPE)
							REBUILD_FINAL_SCOPE.update(REBUILD_EXCLUDE_SCOPE)
							print ("\nFinal Scope:")
							print (json.dumps(REBUILD_FINAL_SCOPE,indent=4))
														
							#set the new payload scope
							ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = REBUILD_FINAL_SCOPE

						else:
							if args.mode == "APD":
								#create the first scope, very similar to ADD function
								ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE

							elif args.mode == "RMV":
								#if the existing environment doesnt have scope, then keep the existing setup and put blank scope
								#Prepare empty scope for discovery
								INPUT_SCOPE = {}
								INPUT_SCOPE["include"] = []
								INPUT_SCOPE["exclude"] = []
								ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE
										
					#Check if the append / remove may cause the included scope to be empty
					#PUT with empty scope will cause error 404
					if not ENV_PAYLOAD["source"]["config"]["aws"]["scope"]["include"]:
						del ENV_PAYLOAD["source"]["config"]["aws"]["scope"]

					#Update the source environment based on env ID and new payload
					ENV_RESULT = put_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID, TARGET_ENV_ID)
					ENV_ID = str(ENV_RESULT['source']['id'])
														
				else:
					print ("Failed to find the environment ID, see response code + reason above, stopping ..")
		
			#Check if environment created / updated properly
			if ENV_ID != "n/a":
				print ("Env ID : " + ENV_ID)
				print ("\n### Cloud Insight Environment created successfully ###")

				#If Scope included, do LAuncher check
				if args.scope and VALID_SCOPE:										
					#Check and wait until launcher completed
					launcher_wait_state(TOKEN, ENV_ID, TARGET_CID, args.mode)
				else:
					print ("\n### No scope defined, skipping Launcher Status ###")

			else:
				print ("### Failed to create / update environment source, see response code + reason above, starting fallback .. ###")
				if args.mode == "DISC":
					failback(TOKEN, CRED_ID, TARGET_CID)

		else:
			print ("\n### Terminating Script ###")

				
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

			#Delete the environment 
			del_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)

			#Check and wait until launcher completed
			launcher_wait_state(TOKEN, TARGET_ENV_ID, TARGET_CID, args.mode)

			#Delete the credentials associated with that environment
			del_source_credentials(TOKEN, TARGET_CRED_ID, TARGET_CID)

		else:
			print ("Failed to find the environment ID, see response code + reason above, stopping ..")

	
	print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")	