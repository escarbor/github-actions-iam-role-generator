# github-actions-iam-role-generator


A Python command line tool for creating simple reduced privilage IAM roles quickly. Specifically with deploying dockerized applications to AWS ECS in mind.

The script uses AWS CloudTrail Event History entries to find which events a previously privlaged run of a deployment created, so the IAM role can be restricted more easily. 

There are some rather open policy statements created by the script, which can be manually updated to restrict further. 

USE:

1) Run deployment with full permissions to generate CloudTrail Events. NOTE: This will only really work on an AWS Account with currently little use. 

2) Create python env and install pip requirements. [See docs](https://virtualenvwrapper.readthedocs.io/en/latest/).

3) Run script. Example:  
`python ./cloud-trail-event-finder.py -u myuser -b bucketname -s '2021-02-26-23:59:59' -e '2021-02-28-23:59:59'`

4) Review output and use to create IAM role policy.


ARGS:

 - -h, --help            show this help message and exit
 
 - -u USER, --user USER  IAM user which this script will trail
 - -b BUCKET_NAME, --bucket_name BUCKET_NAME
                        Optionally pass a bucketname to grant PUT and LIST
                        permissions to. Default is *.
 - -s START_TIME, --start_time START_TIME
                        Start time in utc timestamp, with a default of now,
                        unless defined
-  -e END_TIME, --end_time END_TIME
                        End time in utc timestamp, with a default of 1 hour
                        ago, unless defined