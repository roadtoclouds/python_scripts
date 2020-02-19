
import boto3
from datetime import datetime
from pytz import timezone
import json
import ast


def lambda_handler(event, context):

    current_time_now = datetime.now(timezone('America/Chicago'))
    today_7am = current_time_now.replace(hour=7, minute=0, second=0, microsecond=0)
    today_7pm = current_time_now.replace(hour=19, minute=0, second=0, microsecond=0)


    ec2_client=boto3.client('ec2')
    s3_client=boto3.client('s3')


    running_instances_filter=[
        {
            'Name': 'instance-state-name',
            'Values': ['running', 'stopped']
        }
    ]


    exception_instances_filter=[
        {
        'Name': 'tag:Name',
        'Values': ['True']
        }
    ]


    print("Getting list of all instances...")
    running_instance_list = []
    tags_instance_list = []
    ec2_response_all = ec2_client.describe_instances(Filters=running_instances_filter)
    for instances in ec2_response_all['Reservations']:
        for instance in instances['Instances']:
            running_instance_list.append(instance['InstanceId'])
    print("list of all instances ids {}".format(running_instance_list))


    print("Getting list of all instances with exceptions tags...")
    ec2_response_with_tags = ec2_client.describe_instances(Filters=exception_instances_filter)
    for instances in ec2_response_with_tags['Reservations']:
        for instance in instances['Instances']:
            tags_instance_list.append(instance['InstanceId'])
    print("list of all instances with exception tags {}".format(tags_instance_list))


    print("Updated instance list after removing exception instances...")
    for item in tags_instance_list:
        running_instance_list.remove(item)


    print(running_instance_list)
    s3_response = s3_client.put_object(
        Bucket='s3_bucket',
        Body=bytes(json.dumps(running_instance_list, indent=2).encode('UTF-8')),
        Key='running_instances_list_new.txt'
    )


    if current_time_now < today_7am:
        s3_get_response = s3_client.get_object(
            Bucket='s3_bucket',
            Key='running_instances_list_old.txt'
        )
        instance_list = s3_get_response['Body'].read().decode('utf-8')
        for instance in ast.literal_eval(instance_list):
            print('starting instance {}'.format(instance))
        for instance in all_instance_list:
            print('starting instance {}'.format(instance))
            instance_response = ec2_client.start_instances(
                InstanceIds=[instance],
                DryRun=False,
            )
            print(instance_response)
    elif current_time_now > today_7pm:
        print("Current time has crossed 7PM CST")
        s3_response = s3_client.put_object(
            Bucket='s3_bucket',
            Body=bytes(json.dumps(running_instance_list, indent=2).encode('UTF-8')),
            Key='running_instances_list_old.txt'
        )
        print(s3_response)
        for instance in running_instance_list:
            print('stopping instance {}'.format(instance))
            instance_response = ec2_client.stop_instances(
                InstanceIds=[instance],
                DryRun=False
            )
            print(instance_response)
    else:
        print("Cloud not shutdown/start instances")
