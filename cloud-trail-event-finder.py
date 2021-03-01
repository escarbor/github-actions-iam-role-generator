import boto3
from datetime import datetime, timedelta
import json
import argparse


## Handle args
default_start_time = datetime.utcnow()
default_end_time = datetime.utcnow() + timedelta(hours= 1)
parser = argparse.ArgumentParser(description='Pass a user, start and end datetime and the script returns a IAM policy based on cloudtrail events in the time window provided.')
parser.add_argument("-u", "--user", help="IAM user which this script will trail. REQUIRED", required=True, type=str)
parser.add_argument("-b", "--bucket_name", help="Optionally pass a bucketname to grant PUT and LIST permissions to. Default is *.", default='*')
parser.add_argument("-s", "--start_time", help="Start time in utc timestamp, with a default of now, unless defined", type=lambda s: datetime.strptime(s, '%Y-%m-%d-%H:%M:%S'))
parser.add_argument("-e", "--end_time", help="End time in utc timestamp, with a default of 1 hour ago, unless defined", type=lambda s: datetime.strptime(s, '%Y-%m-%d-%H:%M:%S'))

args = parser.parse_args()

client = boto3.client('cloudtrail')
result_list = []

def get_resources(resources):
    resource_list = []
    for r in resources:
        resource_list.append(r['ARN'])
    return resource_list

def create_policy(raw_json):
    statement_list = []
    for i in raw_json:
        item = json.loads(i)
        statement = {
            "Effect": "Allow",
            "Action": item['action'],
        }
        if item['arn'] != None:
            statement['Resource'] = item['arn']
        statement_list.append(statement)
    
    ## Need this because some actions are not tracked. Not ideal.
    statement_list = add_static_policies(statement_list)
    policy = {
        "Version": "2012-10-17",
        "Statement": statement_list
    }
    return policy

def format_action(event_source, event_name):
    prefix = event_source.split('.')[0]
    sep = '20'
    ## Because some API calls AWS makes have dates tacked on their action names (some sort of code-debt?), but are not recognized by IAM, we need to remove those dates.
    date_stripped_event_name = event_name.split(sep, 1)[0]
    return f'{prefix}:{date_stripped_event_name}'

def retrieve_events(attributes_obj):
    response = client.lookup_events(
        LookupAttributes=attributes_obj,
        StartTime=args.start_time,
        EndTime=args.end_time,
    )
    return response

def add_static_policies(policy_list):
    pass_role = {
        "Effect": "Allow",
        "Action": [
            "iam:PassRole"
        ],
        "Resource": "*"
    }
    policy_list.append(pass_role)
    list_buckets = {
        "Effect": "Allow",
        "Action": [
            "s3:ListBucket",
        ],
        "Resource": f'arn:aws:s3:::{args.bucket_name}' if args.bucket_name != '*' else '*'
    }
    policy_list.append(list_buckets)        
    put_objects = {
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectAcl"
        ],
        "Resource": f'arn:aws:s3:::{args.bucket_name}/*' if args.bucket_name != '*' else '*'
    }
    policy_list.append(put_objects)        
    return policy_list

def parse_events(events):
    for i in events['Events']:
        potential_arn = json.loads(i['CloudTrailEvent']).get('resources')
        obj = {
            "action": format_action(i['EventSource'], i['EventName']),
            "arn": get_resources(potential_arn) if potential_arn != None else ['*']
        }
        result_list.append(json.dumps(obj))
    
# entry point
def run():
    print('Querying CloudTrail Event History for events...')
    print(f'start-time: {args.start_time}')
    print(f'end-time: {args.end_time}')
    
    #Running individual queries and concating their output
    user_query =[{
                'AttributeKey': 'Username',
                'AttributeValue': f'{args.user}'
                },]   
    user_events = retrieve_events(user_query)
    parse_events(user_events)
    sts_query =[{
                'AttributeKey': 'EventSource',
                'AttributeValue': 'sts.amazonaws.com'
                },]
    sts_events = retrieve_events(sts_query)
    parse_events(sts_events)
    ecr_query =[{
                'AttributeKey': 'EventSource',
                'AttributeValue': 'ecr.amazonaws.com'
                },]
    ecr_events = retrieve_events(ecr_query)
    parse_events(ecr_events)
    
    ## Eliminates duplicate entries
    result_set = set(result_list)
    ## Final result as JSON
    print('==============')
    print('**************')
    print('==============')
    print(json.dumps(create_policy(result_set)))

run()