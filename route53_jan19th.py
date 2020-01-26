# Modified by: Chris Sereno 12/03/2019
# To Do:
#   - Compare DynamoDB name with Name tag
#   - Check if Zone Tag matches the DHCP Options set and if they match Route 53 zone if it exists
#   - Use the DHCP options set if it matches zone. Remove Zone tag
############
import json
import boto3
import re
import uuid
import time
import random
import os
from datetime import datetime

print('Loading function ' + datetime.now().time().isoformat())
route53 = boto3.client('route53')
ec2 = boto3.resource('ec2')
compute = boto3.client('ec2')
dynamodb_client = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')
sns_arn = os.environ['snsarn'] #'arn:aws:sns:us-east-1:828272591024:stopEC2dueToSameCnameEntry'
client = boto3.client('sts')
sts_response = client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                      RoleSessionName='AssumeMyRole', DurationSeconds=900)
runstate = {'pending', 'running'}
tagfound = 'false'
namefound = 'false'

def lambda_handler(event, context):
    # Get the state from the Event stream
    state = event['detail']['state']

    # Get the instance id, region, and tag collection
    instance_id = event['detail']['instance-id']
    region = event['region']
    print 'Instance ', instance_id, 'in region ' , region , 'entered state ' , state
   
    """ Check to see whether a DynamoDB table already exists. This table is used to keep a record of
    instances that have been created along with their attributes.  This is necessary because when you terminate an instance
    its attributes are no longer available, so they have to be fetched from the table."""
   
    # *** This table should already be created in SS via CloudFormation***
    dynamodb_client = boto3.client('dynamodb', region_name=region,
                              aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                              aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                              aws_session_token = sts_response['Credentials']['SessionToken'])
    dynamodb_resource = boto3.resource(service_name='dynamodb', region_name=region,
                              aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                              aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                              aws_session_token = sts_response['Credentials']['SessionToken'])
    table = dynamodb_resource.Table('DDNS')
    tables = dynamodb_client.list_tables()
    if 'DDNS' in tables['TableNames']:
        print 'DynamoDB table already exists'
    else:
        create_table('DDNS')


    if state in runstate:
        time.sleep(60)
        instance = compute.describe_instances(InstanceIds=[instance_id])
        # Remove response metadata from the response
        instance.pop('ResponseMetadata')
        # Remove null values from the response.  You cannot save a dict/JSON document in DynamoDB if it contains null
        # values
        instance = remove_empty_from_dict(instance)
        instance_dump = json.dumps(instance,default=json_serial)
        instance_attributes = json.loads(instance_dump)
        try:
            resp = table.put_item(
                Item={
                    'InstanceId': instance_id,
                    'InstanceAttributes': instance_attributes
                }
            )
            print "Added ", instance_id, "to DynamoDB"
            print(resp)
        except BaseException as e:
            print 'ERROR: Unable to add instance to DynamoDB DDNS table: ', e
    else:
        # Fetch item from DynamoDB
        instance = table.get_item(
        Key={
            'InstanceId': instance_id
        },
        AttributesToGet=[
            'InstanceAttributes'
            ]
        )
        instance = instance['Item']['InstanceAttributes']

    try:
        tags = instance['Reservations'][0]['Instances'][0]['Tags']
    except:
        tags = []
    # Get instance attributes
    private_ip = instance['Reservations'][0]['Instances'][0]['PrivateIpAddress']
    private_dns_name = instance['Reservations'][0]['Instances'][0]['PrivateDnsName']
    private_host_name = private_dns_name.split('.')[0]
    try:
        public_ip = instance['Reservations'][0]['Instances'][0]['PublicIpAddress']
        public_dns_name = instance['Reservations'][0]['Instances'][0]['PublicDnsName']
        public_host_name = public_dns_name.split('.')[0]
    except BaseException as e:
        print 'Instance has no public IP or host name', e

    # Get the subnet mask of the instance
    subnet_id = instance['Reservations'][0]['Instances'][0]['SubnetId']
    subnet = ec2.Subnet(subnet_id)
    cidr_block = subnet.cidr_block
    subnet_mask = int(cidr_block.split('/')[-1])

    # Get VPC id
    vpc_id = instance['Reservations'][0]['Instances'][0]['VpcId']
    vpc = ec2.Vpc(vpc_id)

    # Are DNS Hostnames and DNS Support enabled?
    if not is_dns_hostnames_enabled(vpc):
        print 'DNS hostnames disabled for %s.  You have to enable DNS hostnames to use Route 53 private hosted zones.' % vpc_id
    if not is_dns_support_enabled(vpc):
        print 'DNS support disabled for %s.  You have to enabled DNS support to use Route 53 private hosted zones.' % vpc_id

    # Create the public and private hosted zone collections.  These are collections of zones in Route 53.
    hosted_zones = route53.list_hosted_zones()
    private_hosted_zones = filter(lambda x: x['Config']['PrivateZone'] is True, hosted_zones['HostedZones'])
    private_hosted_zone_collection = map(lambda x: x['Name'], private_hosted_zones)
    public_hosted_zones = filter(lambda x: x['Config']['PrivateZone'] is False, hosted_zones['HostedZones'])
    public_hosted_zones_collection = map(lambda x: x['Name'], public_hosted_zones)
   
    # Check to see whether a reverse lookup zone for the instance already exists.  If it does, check to see whether
    # the reverse lookup zone is associated with the instance's VPC.  If it isn't create the association.  You don't
    # need to do this when you create the reverse lookup zone because the association is done automatically.
   
    # Compute the reverse zone
    reversed_ip_address = reverse_list(private_ip)
    reversed_domain_prefix = get_reversed_domain_prefix(subnet_mask, private_ip)
    reversed_domain_prefix = reverse_list(reversed_domain_prefix)

    # Set the reverse lookup zone
    reversed_lookup_zone = reversed_domain_prefix + 'in-addr.arpa.'
    reverse_lookup_zone_id = get_zone_id(reversed_lookup_zone)
    #print 'The reverse lookup zone for this instance is:', reversed_lookup_zone
   
    if filter(lambda record: record['Name'] == reversed_lookup_zone, hosted_zones['HostedZones']):
        print 'Reverse lookup zone found:', reversed_lookup_zone
        reverse_hosted_zone_properties = get_hosted_zone_properties(reverse_lookup_zone_id)
        if vpc_id in map(lambda x: x['VPCId'], reverse_hosted_zone_properties['VPCs']):
            print 'Reverse lookup zone %s is associated with VPC %s' % (reverse_lookup_zone_id, vpc_id)
        else:
            print 'Zone %s not associated with VPC %s' % (reverse_lookup_zone_id, vpc_id)
            exit()
            #print 'Associating zone %s with VPC %s' % (reverse_lookup_zone_id, vpc_id)
            #try:
            #    associate_zone(reverse_lookup_zone_id, region, vpc_id)
            #except BaseException as e:
            #    print e
    else:
        print 'No matching reverse lookup zone'
        # create private hosted zone for reverse lookups
        # if state in runstate:
            #create_reverse_lookup_zone(instance, reversed_domain_prefix, region)
           
    # Wait a random amount of time.  This is a poor-mans back-off if a lot of instances are launched all at once.
    time.sleep(random.random())

    # Loop through the instance's tags, looking for the name and zone tags.  If either of these tags exist, check
    # to make sure that the name is valid.  If it is and if there's a matching zone in DNS, create A and PTR records.
    for tag in tags:      
        if 'ZONE' in tag.get('Key',{}).lstrip().upper():
            tagfound = 'true'
            if is_valid_hostname(tag.get('Value')):
                ZoneName = tag.get('Value').lstrip().lower()
        if 'NAME' in tag.get('Key',{}).lstrip().upper():
            namefound = 'true'
            InstanceName = tag.get('Value')
   
    if tagfound == 'false':
        print "No ZONE tag found. DNS record not being updated."
        exit()
       
    if namefound == 'false':
        print 'No "Name" tag found. DNS record not being updated.'
        exit()
       
    if ZoneName in private_hosted_zone_collection:
        print 'Private zone found: ', ZoneName
        private_hosted_zone_name = ZoneName
        private_hosted_zone_id = get_zone_id(private_hosted_zone_name)
        private_hosted_zone_properties = get_hosted_zone_properties(private_hosted_zone_id)
        #print 'private_hosted_zone_properties', private_hosted_zone_properties
        #all_records_for_hosted_zone = get_all_records_for_hosted_zone(private_hosted_zone_id)
        #print 'all_records_for_hosted_zone', all_records_for_hosted_zone
        if state in runstate:
            if vpc_id not in map(lambda x: x['VPCId'], private_hosted_zone_properties['VPCs']):
                #print 'Private hosted zone %s is associated with VPC %s' % (private_hosted_zone_id, vpc_id)
                print 'Zone %s not associated with VPC %s' % (private_hosted_zone_id, vpc_id)
                exit()
                #print 'Associating zone %s with VPC %s' % (private_hosted_zone_id, vpc_id)
                #try:
                #    associate_zone(private_hosted_zone_id, region, vpc_id)
                #except BaseException as e:
                #    print 'You cannot create an association with a VPC with an overlapping subdomain.\n', e
                #    exit()
            try:
                create_resource_record(private_hosted_zone_id, InstanceName, private_hosted_zone_name, 'A', private_ip)
                #create_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                #create_resource_record(private_hosted_zone_id, InstanceName, private_hosted_zone_name, 'CNAME', private_host_name)
                #create_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
            except BaseException as e:
                print e
        else:
            try:
                delete_resource_record(private_hosted_zone_id, InstanceName, private_hosted_zone_name, 'A', private_ip)
                #delete_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                #delete_resource_record(private_hosted_zone_id, InstanceName, private_hosted_zone_name, 'CNAME', private_host_name)
                #delete_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
            except BaseException as e:
                print e
    # create PTR record
    elif ZoneName in public_hosted_zones_collection:
        print 'Public zone found: ', ZoneName
        public_hosted_zone_name = ZoneName
        public_hosted_zone_id = get_zone_id(public_hosted_zone_name)
        # create A record in public zone
        if state in runstate:
            try:
                create_resource_record(public_hosted_zone_id, InstanceName, public_hosted_zone_name, 'A', public_ip)
                #create_resource_record(public_hosted_zone_id, public_host_name, public_hosted_zone_name, 'A', public_ip)
                #create_resource_record(public_hosted_zone_id, InstanceName, public_hosted_zone_name, 'CNAME', public_host_name)
            except BaseException as e:
                print e
        else:
            try:
                delete_resource_record(public_hosted_zone_id, InstanceName, public_hosted_zone_name, 'A', public_ip)
                #delete_resource_record(public_hosted_zone_id, public_host_name, public_hosted_zone_name, 'A', public_ip)
                #delete_resource_record(public_hosted_zone_id, InstanceName, public_hosted_zone_name, 'CNAME', public_host_name)
            except BaseException as e:
                print e
    else:
        print 'No matching zone found for: ', ZoneName
           

   
       
    # Look to see whether there's a DHCP option set assigned to the VPC.  If there is, use the value of the domain name
    # to create resource records in the appropriate Route 53 private hosted zone. This will also check to see whether
    # there's an association between the instance's VPC and the private hosted zone.  If there isn't, it will create it.
    # Get DHCP option set configuration
    try:
        dhcp_options_id = vpc.dhcp_options_id
        dhcp_configurations = get_dhcp_configurations(dhcp_options_id)
    except BaseException as e:
        print 'No DHCP option set assigned to this VPC\n', e
        exit()
    # Associate the zone
    zonematch = 'false'
    for configuration in dhcp_configurations:
        if configuration[0] in private_hosted_zone_collection:
            zonematch = 'true'
            private_hosted_zone_name = configuration[0]
            print 'Private zone found %s' % private_hosted_zone_name
            # TODO need a way to prevent overlapping subdomains
            private_hosted_zone_id = get_zone_id(private_hosted_zone_name)
            private_hosted_zone_properties = get_hosted_zone_properties(private_hosted_zone_id)
            # create A records and PTR records
            if state in runstate:
                if vpc_id in map(lambda x: x['VPCId'], private_hosted_zone_properties['VPCs']):
                    print 'Private hosted zone %s is associated with VPC %s' % (private_hosted_zone_id, vpc_id)
                else:
                    print 'Zone %s not associated with VPC %s' % (private_hosted_zone_id, vpc_id)
                    #print 'Associating zone %s with VPC %s' % (private_hosted_zone_id, vpc_id)
                    #try:
                    #    associate_zone(private_hosted_zone_id, region,vpc_id)
                    #except BaseException as e:
                    #    print 'You cannot create an association with a VPC with an overlapping subdomain.\n', e
                    exit()
                #try:
                #    create_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                    #create_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
                #except BaseException as e:
                #    print e
            #else:
            #    try:
            #        delete_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                    #delete_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
            #    except BaseException as e:
            #        print e
    if zonematch == 'false':
        print 'No matching zone in DHCP Config Options Set', configuration[0]

    # Clean up DynamoDB after deleting records
    if state not in runstate:
        try:
            table.delete_item(
                Key={
                    'InstanceId': instance_id
                }
            )
        except BaseException as e:
            print e

def create_table(table_name):
    dynamodb_client.create_table(
            TableName=table_name,
            AttributeDefinitions=[
                {
                    'AttributeName': 'InstanceId',
                    'AttributeType': 'S'
                },
            ],
            KeySchema=[
                {
                    'AttributeName': 'InstanceId',
                    'KeyType': 'HASH'
                },
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 4,
                'WriteCapacityUnits': 4
            }
        )
    table = dynamodb_resource.Table(table_name)
    table.wait_until_exists()

def create_resource_record(zone_id, host_name, hosted_zone_name, type, value):
    """This function creates resource records in the hosted zone passed by the calling function."""
    print 'Updating %s record %s in zone %s ' % (type, host_name, hosted_zone_name)
    if host_name[-1] != '.':
        host_name = host_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": host_name + hosted_zone_name,
                                "Type": type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": value
                                    },
                                ]
                            }
                        },
                    ]
                }
            )

def delete_resource_record(zone_id, host_name, hosted_zone_name, type, value):
    """This function deletes resource records from the hosted zone passed by the calling function."""
    print 'Deleting %s record %s in zone %s' % (type, host_name, hosted_zone_name)
    if host_name[-1] != '.':
        host_name = host_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": host_name + hosted_zone_name,
                                "Type": type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": value
                                    },
                                ]
                            }
                        },
                    ]
                }
            )
def get_zone_id(zone_name):
    """This function returns the zone id for the zone name that's passed into the function."""
    if zone_name[-1] != '.':
        zone_name = zone_name + '.'
    hosted_zones = route53.list_hosted_zones()
    x = filter(lambda record: record['Name'] == zone_name, hosted_zones['HostedZones'])
    try:
        zone_id_long = x[0]['Id']
        zone_id = str.split(str(zone_id_long),'/')[2]
        return zone_id
    except:
        return None

def is_valid_hostname(hostname):
    """This function checks to see whether the hostname entered into the zone and cname tags is a valid hostname."""
    if hostname is None or len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def get_dhcp_configurations(dhcp_options_id):
    """This function returns the names of the zones/domains that are in the option set."""
    zone_names = []
    dhcp_options = ec2.DhcpOptions(dhcp_options_id)
    dhcp_configurations = dhcp_options.dhcp_configurations
    for configuration in dhcp_configurations:
        zone_names.append(map(lambda x: x['Value'] + '.', configuration['Values']))
    return zone_names

def reverse_list(list):
    """Reverses the order of the instance's IP address and helps construct the reverse lookup zone name."""
    if (re.search('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',list)) or (re.search('\d{1,3}.\d{1,3}.\d{1,3}\.',list)) or (re.search('\d{1,3}.\d{1,3}\.',list)) or (re.search('\d{1,3}\.',list)):
        list = str.split(str(list),'.')
        list = filter(None, list)
        list.reverse()
        reversed_list = ''
        for item in list:
            reversed_list = reversed_list + item + '.'
        return reversed_list
    else:
        print 'Not a valid ip'
        exit()

def get_reversed_domain_prefix(subnet_mask, private_ip):
    """Uses the mask to get the zone prefix for the reverse lookup zone"""
    if 32 >= subnet_mask >= 24:
        third_octet = re.search('\d{1,3}.\d{1,3}.\d{1,3}.',private_ip)
        return third_octet.group(0)
    elif 24 > subnet_mask >= 16:
        second_octet = re.search('\d{1,3}.\d{1,3}.', private_ip)
        return second_octet.group(0)
    else:
        first_octet = re.search('\d{1,3}.', private_ip)
        return first_octet.group(0)

def create_reverse_lookup_zone(instance, reversed_domain_prefix, region):
    """Creates the reverse lookup zone."""
    print 'Creating reverse lookup zone %s' % reversed_domain_prefix + 'in.addr.arpa.'
    route53.create_hosted_zone(
        Name = reversed_domain_prefix + 'in-addr.arpa.',
        VPC = {
            'VPCRegion':region,
            'VPCId': instance['Reservations'][0]['Instances'][0]['VpcId']
        },
        CallerReference=str(uuid.uuid1()),
        HostedZoneConfig={
            'Comment': 'Updated by Lambda DDNS'
        }
    )

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")

def remove_empty_from_dict(d):
    """Removes empty keys from dictionary"""
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.iteritems() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d

def associate_zone(hosted_zone_id, region, vpc_id):
    """Associates private hosted zone with VPC"""
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=hosted_zone_id,
        VPC={
            'VPCRegion': region,
            'VPCId': vpc_id
        },
        Comment='Updated by Lambda DDNS'
    )

def is_dns_hostnames_enabled(vpc):
    dns_hostnames_enabled = vpc.describe_attribute(
    DryRun=False,
    Attribute='enableDnsHostnames'
)
    return dns_hostnames_enabled['EnableDnsHostnames']['Value']

def is_dns_support_enabled(vpc):
    dns_support_enabled = vpc.describe_attribute(
    DryRun=False,
    Attribute='enableDnsSupport'
)
    return dns_support_enabled['EnableDnsSupport']['Value']

def get_hosted_zone_properties(zone_id):
    hosted_zone_properties = route53.get_hosted_zone(Id=zone_id)
    hosted_zone_properties.pop('ResponseMetadata')
    return hosted_zone_properties