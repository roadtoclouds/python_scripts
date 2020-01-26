#!/usr/bin/python3

import boto3
from pprint import pprint
import json 
import requests

client = boto3.client(
    'ec2',
    aws_access_key_id='',
    aws_secret_access_key=''
)
print(dir(client))
vpc_list = client.describe_vpcs()
print(json.dumps(vpc_list['Vpcs'][0]['VpcId']))


url = "http://reqres.in/api/users?page=2"
payload = {}
headers= {}

response = requests.request("GET", url, headers=headers, data = payload)
pprint(response.content)
# print(response.text.encode('utf8'))
