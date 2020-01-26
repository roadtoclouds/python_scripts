import json
import urllib.parse
import boto3
import ast

print('Loading function')




def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    s3 = boto3.client('s3')
    dynamodb = boto3.client('dynamodb')
    table_name = 'testabc'

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        print("Done, response body:")
        print(response['Body'].read())
        body_bytes = response['Body'].read()
        print("BYTES", body_bytes)
        body_sting = body_bytes.decode("utf-8")
        print("STRING", body_sting)
        
        print('BODY::', body_sting)
        
        # bytes_buffer = io.BytesIO()
        # s3.download_fileobj(Bucket=bucket, Key=key, Fileobj=bytes_buffer)
        # byte_value = bytes_buffer.getvalue()
        # str_value = byte_value.decode()
        # # s3_json_obj = json.dumps(response['Body'].read().decode("utf-8"))
        
        # item = {'test123': body}
        # db_response = dynamodb.put_item(
        #     TableName=table_name,
        #     Item=item)
        # print(db_response)
        return response['ContentType']
        
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e
