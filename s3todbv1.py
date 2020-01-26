import re
import json
import traceback
import boto3

s3_resource = boto3.resource('s3')
s3_client = boto3.client('s3')
dynamodb_client = boto3.client('dynamodb')

table_name = 'test'

def lambda_handler(event, context):
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    # if not key.endswith('/'):
    try:
        split_key = key.split('/')
        file_name = split_key[-1]
        s3_client.download_file(bucket_name, key, '/tmp/'+ file_name)
        with open('/tmp/'+ file_name, 'r') as f:
            db_data = str(f.read().splitlines())
        item = {'test': {'S': db_data}}
        dynamodb_client.put_item(TableName=table_name, Item=item)
        print("Update DynamoDB with S3 bucket file content...")
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        print("S3 file deleted successfully.. ")
        
    except Exception as e:
        print(traceback.format_exc())

    return (bucket_name, key)