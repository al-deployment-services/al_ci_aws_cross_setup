# Wrapper for Alert Logic Cloud Insight deployment via API
# Author: welly.siauw@alertlogic.com
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

from __future__ import print_function
import json, requests, datetime, sys, argparse, time, copy, csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import jsonschema
from jsonschema import validate

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API Endpoint
YARP_URL="api.cloudinsight.alertlogic.com"
ALERT_LOGIC_CI_ASSETS = "https://api.cloudinsight.alertlogic.com/assets/v1/"
ALERT_LOGIC_CI_SOURCE = "https://api.cloudinsight.alertlogic.com/sources/v1/"
ALERT_LOGIC_CI_LAUNCHER = "https://api.cloudinsight.alertlogic.com/launcher/v1/"
ALERT_LOGIC_CI_EXPLORER = "https://api.cloudinsight.alertlogic.com/cloud_explorer/v1/"
ALERT_LOGIC_CI_OTIS = "https://api.cloudinsight.alertlogic.com/otis/v2/"
ALERT_LOGIC_CI_SATURN = "https://api.cloudinsight.alertlogic.com/saturn/v1/"

#exit code standard:
#0 = OK
#1 = argument parser issue
#2 = environment issue such as invalid environment id, invalid password, or invalid scope
#3 = timeout
EXIT_CODE = 0

# Using jsonschema Python library. (http://json-schema.org)
# Schema for scope in Cloud Insight source
scope_schema = {
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

otis_schema = {
	"$schema": "http://json-schema.org/draft-04/schema#",
	"title": "Cloud Insight Otis",
	"description": "Schema for CI Otis options",
	"type": "array",
	"items": {
		"type": "object",
		"properties": {
			"name" : {
				"type": "string",
				"enum": [ "predefined_security_subnet", "num_scanners", "scanner_instance_type", "scanner_autoscaling_enabled", "scanner_additional_resource_tags"]
			},
			"scope": {
				"type": "object",
				"properties": {
					"provider_type" : {
						"type": "string",
						"enum": ["aws"]
					},
					"provider_id" : {
						"type": "string",
						"pattern" : "^([0-9]{12})$"
					},
					"vpc_id" : {
						"type": "string",
						"pattern" : "^(vpc-)([a-z0-9]{8}|[a-z0-9]{17})$"
					}
				}
			},
			"value": {
				"type": "string",
				"pattern" : "^(subnet-)([a-z0-9]{8}|[a-z0-9]{17})$"
			}
		},
		"required": ["name", "scope", "value"]
	},
	"minItems": 1,
	"uniqueItems": True
}


def schema_check(json_data, _schema):
	print("Validate input using the following schema:")
	print(json.dumps(_schema, indent=4))

	# The data to be validated:
	data =[]
	data.append(json_data)

	print("\nRaw input data:")
	print(json.dumps(data, indent=4))

	print("Validation input data using the schema:")
	for idx, item in enumerate(data):
		try:
			validate(item, _schema)
			sys.stdout.write("Record #{}: OK\n".format(idx))
			return True
		except jsonschema.exceptions.ValidationError as ve:
			sys.stderr.write("Record #{}: ERROR\n".format(idx))
			sys.stderr.write(str(ve) + "\n")
			return False

def scope_csv_to_json(csv_raw):
	CSV_READER = csv.reader(csv_raw, delimiter=",")
	RESULT = {}
	RESULT["include"] = []
	RESULT["exclude"] = []
	for row in CSV_READER:
		TEMP = {}
		if row[1] == "vpc":
			TEMP["key"] = "/aws/" + row[2] + "/vpc/" + row[3]
		elif row[1] == "region":
			TEMP["key"] = "/aws/" + row[2]
		TEMP["type"] = row[1]
		RESULT[row[0]].append(TEMP)
	return RESULT

def otis_csv_to_json(csv_raw):
	CSV_READER = csv.reader(csv_raw, delimiter=",")
	RESULT = []
	for row in CSV_READER:
		TEMP = {}
		TEMP["name"] = row[0]
		if row[0] == "predefined_security_subnet":
			TEMP["scope"] = {}
			TEMP["scope"]["provider_type"] = "aws"
			TEMP["scope"]["provider_id"] = row[1]
			TEMP["scope"]["vpc_id"] = row[2]
			TEMP["value"] = row[3]
		RESULT.append(TEMP)
	return RESULT

def open_input_file(file_path, otis = False):
	try:
		with open(file_path) as input_data:
			if file_path.split(".")[len(file_path.split("."))-1] == "json":
				RESULT = json.load(input_data)
			elif file_path.split(".")[len(file_path.split("."))-1] == "csv":
				if otis:
					RESULT = otis_csv_to_json(input_data)
				else:
					RESULT = scope_csv_to_json(input_data)
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

def prep_ci_source_environment(aws_account, cred_id, environment_name, scope_data, enable_otis = False):
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
	if enable_otis:
		RESULT['source']['config']['deployment_mode'] = "guided"
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

def post_otis_options(token, payload, target_cid):
	#Call API with method POST to create new environment
	API_ENDPOINT = ALERT_LOGIC_CI_OTIS + target_cid + "/options"
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False, data=payload)
	print ("Add Otis Options Status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:
		RESULT = json.loads(REQUEST.text)
	else:
		RESULT = {}
		RESULT['id'] = "n/a"
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

def get_saturn_status(token, target_env, target_cid):
	#Check if Launcher is completed
	API_ENDPOINT = ALERT_LOGIC_CI_SATURN + target_cid + "/installations?deployment_id=" + target_env
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)

	print ("Retrieving Environment launch status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 200:
		RESULT = json.loads(REQUEST.text)
	else:
		RESULT = False
	return RESULT

def post_ci_discovery(token, target_env, target_cid, target_type):
	#Force environment discovery
	API_ENDPOINT = ALERT_LOGIC_CI_EXPLORER + target_cid + "/environments/" + target_env + "/discover/" + target_type
	REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	RESULT = REQUEST.status_code
	return RESULT

def get_ci_asset(token, target_env, target_cid, target_id, target_type):
	#count CI assets based on given CID, ENV ID, KEY and ASSET TYPE
	API_ENDPOINT = ALERT_LOGIC_CI_ASSETS + target_cid + "/environments/" + target_env + "/assets?asset_types=a:" + target_type + "&a.key=" + target_id
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	RESULT = json.loads(REQUEST.text)
	return RESULT["rows"]

def get_vpc_status(token, target_env, target_cid, target_vpc_list, timeout):
	#Wait for all vpc asset to be available (via discovery every 60 seconds)
	global EXIT_CODE
	TIMEOUT_COUNTER=60

	print ("\n### Start of target asset (vpc) validation ###")

	VPC_STATUS = False
	while VPC_STATUS == False:
		VPC_STATUS = True
		for vpc_key in target_vpc_list:
			VPC_COUNT = get_ci_asset(token, target_env, target_cid, str(vpc_key), "vpc")
			if VPC_COUNT == 0:
				print ("- Cannot find target asset: " + str(vpc_key))
				VPC_STATUS = False

		if VPC_STATUS == True:
			print ("- All target asset found - continue to launch")
			break
		else:
			DISCOVERY_STATUS = post_ci_discovery(token, target_env, target_cid, "ec2/vpc")
			print ("Re-Discovery status:" + str(DISCOVERY_STATUS) + " - waiting for 60 seconds\n")

		#reduce counter up to the limit timeout
		timeout = timeout - TIMEOUT_COUNTER
		if timeout < 0:
			print ("\n### Script timeout exceeded ###")
			EXIT_CODE=3
			break;
		else:
			time.sleep(60)

	print ("\n### End of target asset (vpc) validation ###\n")

	return VPC_STATUS

def launcher_filter_output(token, target_env, target_cid, mode, scope_filter):
	print ("### Filter output, show only changes to environment - mode : " + str(mode) + " ###")

	#grab launcher data
	LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)
	if LAUNCHER_RESULT["scope"] != "n/a":
		LAUNCHER_DATA = get_launcher_data(token, target_env, target_cid)
		if LAUNCHER_DATA["environment_id"] != "n/a":
			#if the new scope is not empty, retrieve the launcher info for resource that changes (added or removed)
			if scope_filter:
				for LAUNCHER_VPC in LAUNCHER_DATA["vpcs"]:
					for vpc in scope_filter:
						if vpc == LAUNCHER_VPC["vpc_key"]:
							print ("Change_Region: " + str(LAUNCHER_VPC["region"]))
							print ("Change_VPC: " + str(LAUNCHER_VPC["vpc_key"]))
							print ("Change_SG: " + str(LAUNCHER_VPC["security_group"]["resource_id"]))
							print ("\n")

	print ("### End Filter Output ###\n")

def launcher_wait_state(token, target_env, target_cid,mode, timeout):
	#Wait for launcher to be fully deployed
	global EXIT_CODE
	TIMEOUT_COUNTER=10

	print ("\n### Start of Check Launcher Status ###")

	#give sufficient time for backend to update Launcher status
	time.sleep(10)
	LAUNCHER_STATUS = True

	while True:
		if mode == "ADD" or mode == "DISC" or mode =="APD" or mode =="RMV":
			#Get Launcher Status and check for each region / VPC
			LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)
			if LAUNCHER_RESULT["scope"] != "n/a":
				LAUNCHER_FLAG = True

				for LAUNCHER_REGION in LAUNCHER_RESULT["scope"]:
					print ("Region : " + str(LAUNCHER_REGION["key"])  + " status : " + str(LAUNCHER_REGION["protection_state"]) )
					if LAUNCHER_REGION["protection_state"] == "failed":
						#this can occur due to launcher can't see the VPC yet, throw this back
						LAUNCHER_STATUS = False
						LAUNCHER_FLAG = False

					elif LAUNCHER_REGION["protection_state"] != "completed" and LAUNCHER_REGION["protection_state"] != "removed":
						LAUNCHER_STATUS = True
						LAUNCHER_FLAG = False

				#this indicate a failure in launcher that needs to be returned
				if LAUNCHER_STATUS == False:
					print ("\n### One of the launcher failed - returning to retry launch ###")
					break
				elif LAUNCHER_FLAG == True:
					print ("\n### Launcher Completed Successfully ###")
					LAUNCHER_RETRY = 5
					LAUNCHER_STATUS = True

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
							if LAUNCHER_RETRY <= 0: EXIT_CODE=3

					break


			else:
				#Launcher did not execute for any reason
				LAUNCHER_FLAG = False
				LAUNCHER_STATUS = False
				print ("\n### One of the launcher failed - returning to retry launch ###")
				break;

		elif mode == "DEL":
			#Get Launcher Status
			LAUNCHER_RESULT = get_launcher_status(token, target_env, target_cid)

			if LAUNCHER_RESULT["scope"] == "n/a":
				print ("\n### Launcher Deleted Successfully ###")
				break;

		#Sleep for 10 seconds
		timeout = timeout - TIMEOUT_COUNTER
		if timeout < 0:
			print ("\n### Script timeout exceeded ###")
			EXIT_CODE=3
			break;

		time.sleep(TIMEOUT_COUNTER)

	print ("### End of Check Launcher Status ###\n")
	return LAUNCHER_STATUS

def saturn_wait_state(token, target_env, target_cid, mode, timeout):
	#Wait for SATURN to be fully deployed
	global EXIT_CODE
	TIMEOUT_COUNTER=10

	print ("\n### Start of Check Saturn Status ###")

	#give sufficient time for backend to update SATURN status
	time.sleep(10)

	#Make sure environment in OK status before performing saturn check
	if mode == "ADD" or mode == "DISC" or mode =="APD" or mode =="RMV":
		print ("### Review the CI environment status after create/update ###")
		env_timeout = timeout
		while True:
			ENV_RESULT = get_source_environment(token, target_env, target_cid)
			if ENV_RESULT["source"]["id"] != "n/a":
				print ("Environment: " + str(target_env) + " status: " + str(ENV_RESULT["source"]["status"]["status"]))
				if ENV_RESULT["source"]["status"]["status"] == "ok":
					print ("Environment ready - continue with Saturn check")
					break
				else:
					print ("Environment not ready, waiting ...")
			else:
				print ("\n### Failed to check Source - script may timeout before saturn check completed ###")

			#Sleep for 10 seconds
			env_timeout = env_timeout - TIMEOUT_COUNTER
			if env_timeout < 0:
				print ("\n### Timeout while waiting for environment change to OK - script may timeout before saturn check completed ###")
				EXIT_CODE=3
				break;
			time.sleep(TIMEOUT_COUNTER)

	SATURN_STATUS = True
	while True:
		if mode == "ADD" or mode =="APD" or mode =="RMV":
			#Get SATURN Status and check for each region / VPC
			SATURN_RESULT = get_saturn_status(token, target_env, target_cid)
			if SATURN_RESULT != False and len(SATURN_RESULT) > 0:
				SATURN_FLAG = True
				for SATURN_VPC in SATURN_RESULT:
					print ("VPC: " + str(SATURN_VPC["vpc_key"])  + " state: " + str(SATURN_VPC["status"]["state"]) )
					if SATURN_VPC["status"]["state"]["status"] != "completed" and SATURN_VPC["status"]["state"]["operation"] == "deploy":
						SATURN_STATUS = True
						SATURN_FLAG = False
					elif SATURN_VPC["status"]["state"]["status"] != "completed" and SATURN_VPC["status"]["state"]["operation"] == "remove":
						SATURN_STATUS = True
						SATURN_FLAG = False

				#this indicate a failure in SATURN that needs to be returned
				if SATURN_STATUS == False:
					print ("\n### One of the SATURN failed - returning to retry launch ###")
					break
				elif SATURN_FLAG == True:
					SATURN_STATUS = True
					print ("\n### SATURN Completed Successfully ###")
					print ("\n### Successfully retrieve SATURN data ###")

					for SATURN_VPC in SATURN_RESULT:
						print ("Region: " + str(SATURN_VPC["vpc_key"].split("/")[2]))
						print ("VPC: " + str(SATURN_VPC["vpc_key"].split("/")[4]))
						print ("SG: " + str((resource for resource in SATURN_VPC["resources"] if resource["type"] == "security_group").next()["details"]["group_id"]))
						print ("\n")
					break
			elif len(SATURN_RESULT) == 0:
				if mode == "RMV":
					print ("\n### SATURN Status Removed Successfully ###")
					break
				else:
					print ("\n### SATURN data not ready, waiting ... ###")
			else:
				#SATURN did not execute for any reason
				SATURN_FLAG = False
				SATURN_STATUS = False
				print ("\n### One of the SATURN failed - returning to retry launch ###")
				break;

		elif mode == "DISC":
			print ("\n### Mode: DISC - skip SATURN check###")
			break
		elif mode == "DEL":
			#Get SATURN Status
			SATURN_RESULT = get_saturn_status(token, target_env, target_cid)
			if SATURN_RESULT != False and len(SATURN_RESULT) > 0:
				for SATURN_VPC in SATURN_RESULT:
					print ("VPC: " + str(SATURN_VPC["vpc_key"])  + " state: " + str(SATURN_VPC["status"]["state"]) )

			if len(SATURN_RESULT) == 0:
				print ("\n### SATURN Deleted Successfully ###")
				break;
			elif SATURN_RESULT == False:
				print ("\n### SATURN retrival failed ###")
				break;

		#Sleep for 10 seconds
		timeout = timeout - TIMEOUT_COUNTER
		if timeout < 0:
			print ("\n### Script timeout exceeded ###")
			EXIT_CODE=3
			break;

		time.sleep(TIMEOUT_COUNTER)

	print ("### End of Check SATURN Status ###\n")
	return SATURN_STATUS

def change_scope_to_list(input_scope, scope_type):
	temp_list = []

	for item in input_scope:
		if item["type"] == scope_type:
			temp_list.append(item["key"])

	return temp_list

def filter_scope(source_scope, new_scope, scope_type, mode):

	source_scope = change_scope_to_list(source_scope, scope_type)
	new_scope = change_scope_to_list(new_scope, scope_type)

	#find the resultant changes
	if mode == "APD" or mode == "DISC":
		difference_scope = set(new_scope) - set(source_scope)

	elif mode == "RMV":
		difference_scope = set(source_scope) - (set(source_scope) - set(new_scope))

	elif mode == "ADD":
		difference_scope = set(new_scope + source_scope)

	return difference_scope

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
	EXIT_CODE=0
	#Default timeout set to 600 seconds
	SCRIPT_TIMEOUT = 600

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
	dis_parser.add_argument("--time", required=False, help="Time out in second for this script to run")
	dis_parser.add_argument("--filter", required=False, help="Filter the output to only show the new changes", default=False, action='store_true')
	dis_parser.add_argument("--skip", required=False, help="Skip schema validation check", default=True, action='store_false')
	dis_parser.add_argument("--otis", required=False, help="Path to CSV file for Otis / CI Guided config")

	#Parser argument for Add scope
	add_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	add_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	add_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	add_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	add_parser.add_argument("--scope", required=True, help="Path to JSON/CSV file with the region / scope scope detail")
	add_parser.add_argument("--time", required=False, help="Time out in second for this script to run")
	add_parser.add_argument("--filter", required=False, help="Filter the output to only show the new changes", default=False, action='store_true')
	add_parser.add_argument("--skip", required=False, help="Skip schema validation check", default=True, action='store_false')
	add_parser.add_argument("--otis", required=False, help="Path to CSV file for Otis / CI Guided config")

	#Parser argument for Delete environment
	del_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	del_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	del_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for removal")
	del_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for removal")
	del_parser.add_argument("--time", required=False, help="Time out in second for this script to run")
	del_parser.add_argument("--filter", required=False, help="Filter the output to only show the new changes", default=False, action='store_true')
	del_parser.add_argument("--skip", required=False, help="Skip schema validation check", default=True, action='store_false')

	#Parser argument for Append scope
	apd_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	apd_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	apd_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	apd_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	apd_parser.add_argument("--scope", required=True, help="Path to JSON file with the region / scope scope detail")
	apd_parser.add_argument("--time", required=False, help="Time out in second for this script to run")
	apd_parser.add_argument("--filter", required=False, help="Filter the output to only show the new changes", default=False, action='store_true')
	apd_parser.add_argument("--skip", required=False, help="Skip schema validation check", default=True, action='store_false')
	apd_parser.add_argument("--otis", required=False, help="Path to CSV file for Otis / CI Guided config")

	#Parser argument for Remove scope
	rmv_parser.add_argument("--user", required=True, help="User name / email address for API Authentication")
	rmv_parser.add_argument("--pswd", required=True, help="Password for API Authentication")
	rmv_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target for adding scope")
	rmv_parser.add_argument("--envid", required=True, help="Cloud Insight Environment ID as target for this scope")
	rmv_parser.add_argument("--scope", required=True, help="Path to JSON file with the region / scope scope detail")
	rmv_parser.add_argument("--time", required=False, help="Time out in second for this script to run")
	rmv_parser.add_argument("--filter", required=False, help="Filter the output to only show the new changes", default=False, action='store_true')
	rmv_parser.add_argument("--skip", required=False, help="Skip schema validation check", default=True, action='store_false')
	rmv_parser.add_argument("--otis", required=False, help="Path to CSV file for Otis / CI Guided config")

	try:
		args = parent_parser.parse_args()
	except:
		EXIT_CODE = 1
		sys.exit(EXIT_CODE)

	TARGET_FILTER = False

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
		ENFORCE_SCHEMA = args.skip
		TARGET_OTIS = args.otis

	elif args.mode == "ADD" or args.mode == "APD" or args.mode == "RMV":
		EMAIL_ADDRESS = args.user
		PASSWORD = args.pswd
		TARGET_CID = args.cid
		TARGET_ENV_ID = args.envid
		TARGET_SCOPE = args.scope
		ENFORCE_SCHEMA = args.skip
		TARGET_OTIS = args.otis

	elif args.mode == "DEL":
		EMAIL_ADDRESS = args.user
		PASSWORD = args.pswd
		TARGET_CID = args.cid
		TARGET_ENV_ID = args.envid
		ENFORCE_SCHEMA = args.skip

	#Initialize output filter
	TARGET_FILTER = args.filter
	SCOPE_DIFFERENCE = []

	if args.time:
		SCRIPT_TIMEOUT=int(args.time)

	if args.mode =="DISC" or args.mode == "ADD" or args.mode =="APD" or args.mode =="RMV":
		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = " + str(args.mode) + " ###\n")

		#Authenticate with Cloud Insight and retrieve token
		try:
			TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		except:
			print ("### Cannot Authenticate - check user name or password ###\n")
			EXIT_CODE = 2
			sys.exit(EXIT_CODE)

		#Check if scope provided
		VALID_SCOPE = True
		if args.scope:
			#Read scope file
			print ("### Reading input file ... ###")
			INPUT_SCOPE = []
			INPUT_SCOPE = open_input_file(TARGET_SCOPE)

			if INPUT_SCOPE != False:
				#Check input file against the json schema to make sure it's valid
				if schema_check(INPUT_SCOPE, scope_schema) and ENFORCE_SCHEMA == True:
					print ("\n### Input Schema validation OK - continue to add / update / remove the environment scope ###")
					VALID_SCOPE = True

				elif ENFORCE_SCHEMA == False:
					print ("\n### WARNING Input Schema validation SKIPPED - continue to add / update / remove the environment scope ###")
					VALID_SCOPE = True
				else:
					print ("\n### Input Schema validation issues, please read error message above ###")
					VALID_SCOPE = False

			else:
				#Cannot find or open the scope file
				VALID_SCOPE = False

		else:
			print ("### No scope included ###")
			VALID_SCOPE = False

		#Check if otis config provided
		VALID_OTIS = True
		if args.otis:
			#Read otis file
			print ("### Reading otis options file ... ###")
			OTIS_OPTIONS = []
			OTIS_OPTIONS = open_input_file(TARGET_OTIS, otis=True)

			if OTIS_OPTIONS != False:
				#Check otis against the json schema
				if schema_check(OTIS_OPTIONS, otis_schema) and ENFORCE_SCHEMA == True:
					print ("\n### Otis Schema validation OK - continue to add / update / remove the environment scope ###")
					VALID_OTIS = True
				elif ENFORCE_SCHEMA == False:
					print ("\n### WARNING Otis Schema validation SKIPPED - continue to add / update / remove the environment scope ###")
					VALID_OTIS = True
				else:
					print ("\n### Input Schema validation issues, please read error message above ###")
					VALID_OTIS = False
			else:
				#Cannot find or open the otis option file
				VALID_SCOPE = False
		else:
			print ("### No otis options included ###")
			VALID_OTIS = False

		#TODO: add otis config
		if VALID_OTIS:
			for options in OTIS_OPTIONS:
				OPTION_RESULT = post_otis_options(TOKEN, json.dumps(options, indent=3), TARGET_CID)
				OPTION_ID = str(OPTION_RESULT['id'])
				if OPTION_ID != "n/a":
					print ("Otis options: " + options["name"] + " value: " + options["value"] + " id: " + OPTION_ID)
				else:
					print ("Otis options: " + options["name"] + " value: " + options["value"] + " create failed")

		#Handling missing scope
		NO_LAUNCHER = False
		if VALID_SCOPE == False and args.mode == "DISC":
			print ("\n### Deployment will continue with empty scope ###")

			#Prepare empty scope for discovery
			INPUT_SCOPE = {}
			INPUT_SCOPE["include"] = []
			INPUT_SCOPE["exclude"] = []
			VALID_SCOPE = True
			NO_LAUNCHER = True

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
				#if Otis enabled, launch with blank scope first
				if VALID_OTIS:
					#Prepare empty scope for discovery
					INPUT_SCOPE = {}
					INPUT_SCOPE["include"] = []
					INPUT_SCOPE["exclude"] = []
					ENV_PAYLOAD = prep_ci_source_environment(TARGET_AWS_ACCOUNT, CRED_ID, TARGET_ENV_NAME, INPUT_SCOPE, enable_otis = VALID_OTIS)
				else:
					ENV_PAYLOAD = prep_ci_source_environment(TARGET_AWS_ACCOUNT, CRED_ID, TARGET_ENV_NAME, INPUT_SCOPE, enable_otis = VALID_OTIS)

				#Create new environment to kick discovery
				ENV_RESULT = post_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID)
				ENV_ID = str(ENV_RESULT['source']['id'])

				#if Output filter is set, get the resultant scope
				if TARGET_FILTER == True:
					#create dummy source to calculate the resultant output
					DUMMY_SOURCE = {}
					DUMMY_SOURCE["include"] = []
					DUMMY_SOURCE["exclude"] = []

					SCOPE_DIFFERENCE = filter_scope(DUMMY_SOURCE["include"], INPUT_SCOPE["include"], "vpc", args.mode)

			elif args.mode == "ADD" or args.mode == "APD" or args.mode =="RMV":

				#Check if the provided Environment ID exist and valid
				SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)

				if SOURCE_RESULT["source"]["id"] != "n/a":

					#Build new payload based on original source + new scope
					ENV_PAYLOAD = copy.deepcopy(SOURCE_RESULT)

					#clean up fiedls that is not required
					if ENV_PAYLOAD["source"].has_key("created"): del ENV_PAYLOAD["source"]["created"]
					if ENV_PAYLOAD["source"].has_key("modified"): del ENV_PAYLOAD["source"]["modified"]

					#For Add mode, just use the input scope to replace existing scope
					if args.mode =="ADD":
						ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE
						if SOURCE_RESULT["source"]["config"]["aws"].has_key("scope"):
							EXISTING_SCOPE = True
						else:
							EXISTING_SCOPE = False

					#For Append mode, add the new scope to the existing scope
					#For Remove mode, subtract the new scope from existing scope
					elif args.mode =="APD" or args.mode == "RMV":

						#Check if the existing environment has scope included
						if SOURCE_RESULT["source"]["config"]["aws"].has_key("scope"):
							#verify if the scope if empty
							if SOURCE_RESULT["source"]["config"]["aws"]["scope"]:
								EXISTING_SCOPE = True
							else:
								#to accomodate issue where environment has been de-scoped from the UI with artifact key: scope still exist in the Source
								EXISTING_SCOPE = False
						else:
							EXISTING_SCOPE = False


						if EXISTING_SCOPE == True:
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

							#merge both include and excluded scope and prepare the new payload
							REBUILD_FINAL_SCOPE = {}
							REBUILD_FINAL_SCOPE.update(REBUILD_INCLUDE_SCOPE)
							REBUILD_FINAL_SCOPE.update(REBUILD_EXCLUDE_SCOPE)

							print ("\nOriginal Scope:")
							print (json.dumps(SOURCE_RESULT["source"]["config"]["aws"]["scope"], indent=4))

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
								#Prepare empty scope
								INPUT_SCOPE = {}
								INPUT_SCOPE["include"] = []
								INPUT_SCOPE["exclude"] = []
								ENV_PAYLOAD["source"]["config"]["aws"]["scope"] = INPUT_SCOPE

							print ("\nOriginal Scope:")
							print ("-- original scope is empty --")

							print ("\nFinal Scope:")
							print (json.dumps(INPUT_SCOPE,indent=4))

					#Check if the append / remove may cause the included scope to be empty
					#PUT with empty scope will cause error 404
					if not ENV_PAYLOAD["source"]["config"]["aws"]["scope"]["include"]:
						del ENV_PAYLOAD["source"]["config"]["aws"]["scope"]

					#Find the resultant output after changes applied (ADD / APD / RMV)
					if EXISTING_SCOPE == True:
						SCOPE_DIFFERENCE = filter_scope(SOURCE_RESULT["source"]["config"]["aws"]["scope"]["include"], INPUT_SCOPE["include"], "vpc", args.mode)
					else:
						#create dummy source to calculate the resultant scope
						DUMMY_SOURCE = {}
						DUMMY_SOURCE["include"] = []
						DUMMY_SOURCE["exclude"] = []
						SCOPE_DIFFERENCE = filter_scope(DUMMY_SOURCE["include"], INPUT_SCOPE["include"], "vpc", args.mode)

					if TARGET_FILTER == True and args.mode == "RMV":
						#If mode = remove, display the changes before we delete it, otherwise we lose the aws resource info
						#for other mode (add, apd, disc) wait until the launcher is set before take the filter output
						launcher_filter_output(TOKEN, TARGET_ENV_ID, TARGET_CID, args.mode, SCOPE_DIFFERENCE)

					#Check and make sure the vpc is read-able before adding to scope
					#otherwise the launcher may failed in infinite loop because it can't launch in non-existant VPC
					if args.mode == "APD" or args.mode =="ADD":
						VALID_TARGET = get_vpc_status(TOKEN, TARGET_ENV_ID, TARGET_CID, SCOPE_DIFFERENCE, SCRIPT_TIMEOUT)
						# run this to trigger syntetic error for launcher VALID_TARGET = True
						ENV_ID = "n/a"
					else:
						VALID_TARGET = True
						ENV_ID = "n/a"

					if VALID_TARGET == True:
						#Update the source environment based on env ID and new payload
						ENV_RESULT = put_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID, TARGET_ENV_ID)
						ENV_ID = str(ENV_RESULT['source']['id'])
					else:
						EXIT_CODE=2
						print ("Failed to find target VPC to launch")
				else:
					print ("Failed to find the environment ID, see response code + reason above, stopping ..")

			#Check if environment created / updated properly
			if ENV_ID != "n/a":
				print ("Env ID : " + ENV_ID)
				print ("\n### Cloud Insight Environment created successfully ###")

				#If Scope included, do Launcher check
				if args.scope and NO_LAUNCHER == False:

					#Check and wait until launcher completed
					LAUNCHER_WAIT_STATE_COUNTER = 5

					#TODO : conditional for otis (saturn) vs launcher
					if VALID_OTIS:
						while saturn_wait_state(TOKEN, ENV_ID, TARGET_CID, args.mode, SCRIPT_TIMEOUT) == False:
							time.sleep(10)
							print ("\n### Retry Environment Update ###")
							#Update the source environment based on env ID and new payload
							ENV_RESULT = put_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID, ENV_ID)

							if LAUNCHER_WAIT_STATE_COUNTER > 0:
								LAUNCHER_WAIT_STATE_COUNTER = LAUNCHER_WAIT_STATE_COUNTER -1
							else:
								EXIT_CODE = 3
								print ("\n### Retry limit reached - cancel deployment ###")
								print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")
								sys.exit(EXIT_CODE)

					else:
						while launcher_wait_state(TOKEN, ENV_ID, TARGET_CID, args.mode, SCRIPT_TIMEOUT) == False:
							time.sleep(10)
							print ("\n### Retry Environment Update ###")
							#Update the source environment based on env ID and new payload
							ENV_RESULT = put_source_environment(TOKEN, str(json.dumps(ENV_PAYLOAD, indent=4)), TARGET_CID, ENV_ID)

							if LAUNCHER_WAIT_STATE_COUNTER > 0:
								LAUNCHER_WAIT_STATE_COUNTER = LAUNCHER_WAIT_STATE_COUNTER -1
							else:
								EXIT_CODE = 3
								print ("\n### Retry limit reached - cancel deployment ###")
								print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")
								sys.exit(EXIT_CODE)

					#If mode = append, add or discovery, then display the changes after we create it
					if TARGET_FILTER == True:
						if args.mode == "APD" or args.mode == "ADD" or args.mode =="DISC":
							if not args.otis:
								launcher_filter_output(TOKEN, ENV_ID, TARGET_CID, args.mode, SCOPE_DIFFERENCE)

				else:
					print ("\n### No scope defined, skipping Launcher Status ###")

			else:
				print ("### Failed to create / update environment source, see response code + reason above, starting fallback .. ###")
				if args.mode == "DISC":
					failback(TOKEN, CRED_ID, TARGET_CID)
				EXIT_CODE = 2

		else:
			print ("\n### Terminating Script ###")
			EXIT_CODE = 2


	elif args.mode == "DEL":

		print ("### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = Delete ###\n")

		#Authenticate with Cloud Insight and retrieve token
		try:
			TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))
		except:
			print ("### Cannot Authenticate - check user name or password ###\n")
			EXIT_CODE = 2
			sys.exit(EXIT_CODE)

		#Check if the provided Environment ID exist and valid
		SOURCE_RESULT = get_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)

		if SOURCE_RESULT["source"]["id"] != "n/a":
			TARGET_CRED_ID = SOURCE_RESULT["source"]["config"]["aws"]["credential"]["id"]
			print ("Env ID : " + TARGET_ENV_ID)
			print ("Credential ID : " + TARGET_CRED_ID)

			#Delete the environment
			del_source_environment(TOKEN, TARGET_ENV_ID, TARGET_CID)

			#Check and wait until launcher completed
			if SOURCE_RESULT["source"]["config"]["deployment_mode"] == "guided":
				saturn_wait_state(TOKEN, TARGET_ENV_ID, TARGET_CID, args.mode, SCRIPT_TIMEOUT)
			else:
				launcher_wait_state(TOKEN, TARGET_ENV_ID, TARGET_CID, args.mode, SCRIPT_TIMEOUT)

			#Delete the credentials associated with that environment
			del_source_credentials(TOKEN, TARGET_CRED_ID, TARGET_CID)

		else:
			EXIT_CODE=2
			print ("Failed to find the environment ID, see response code + reason above, stopping ..")


	print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")
	sys.exit(EXIT_CODE)
