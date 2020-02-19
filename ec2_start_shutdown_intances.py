import boto3
from datetime import datetime
from pytz import timezone

def lambda_handler(event, context):

    current_time_now = datetime.now(timezone('America/Chicago'))
    today_7am = current_time_now.replace(hour=7, minute=0, second=0, microsecond=0)
    today_6_30pm = current_time_now.replace(hour=18, minute=30, second=0, microsecond=0)

    ec2_client = boto3.client('ec2')

    filters = [{
        'Name': 'tag:Name',
        'Values': ['']
    }]

    print("Getting list of all instances...")
    all_instance_list = []
    tags_instance_list = []
    ec2_response_all = ec2_client.describe_instances()
    for instances in ec2_response_all['Reservations']:
        for instance in instances['Instances']:
            all_instance_list.append(instance['InstanceId'])
    print("list of all instances ids {}".format(all_instance_list))

    print("Getting list of all instances with exceptions tags...")
    ec2_response_with_tags = ec2_client.describe_instances(Filters=filters)
    for instances in ec2_response_with_tags['Reservations']:
        for instance in instances['Instances']:
            tags_instance_list.append(instance['InstanceId'])
    print("list of all instances with exception tags {}".format(tags_instance_list))

    print("Updated instance list after removing exception instances...")
    for item in tags_instance_list:
        all_instance_list.remove(item)

    print(all_instance_list)

    if current_time_now < today_7am:
        print('7AM')
        for instance in all_instance_list:
            print('shutting down instance {}'.format(instance))
            instance_response = ec2_client.start_instances(
                InstanceIds=[instance],
                DryRun=False
            )
            print(instance_response)
    elif current_time_now > today_6_30pm:
        print('6_30PM')
        for instance in all_instance_list:
            print('starting instance {}'.format(instance))
            instance_response = ec2_client.stop_instances(
                InstanceIds=[instance],
                DryRun=False
            )
            print(instance_response)
    else:
        print("Cloud not shutdown/start instances")
