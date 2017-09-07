import os
import sys

# Only load linux-compiled dependencies if executing under linux
if sys.platform.startswith('linux'):
  here = os.path.dirname(os.path.realpath(__file__))
  sys.path.append(os.path.join(here, "vendored"))

import awstrust
import boto3
import botocore
import datetime
import functools
import hashlib
import json
import logging
import pymemcache.client.base
import time
import urllib
from envparse import env


# AWS_ASSUME_ROLES is a list of role ARNs this function can assume
# to call DescribeInstances in different AWS accounts.
AWS_ASSUME_ROLES = env(
  'AWS_ASSUME_ROLES',
  default=[],
  cast=list,
  subcast=str,
  )

# Python log level (https://docs.python.org/2/library/logging.html#levels)
LOG_LEVEL = env(
  'LOG_LEVEL',
  default='debug',
  cast=str,
  )

# INHERIT_TAGS is a comma separated list of tag prefixes inherited
# from parent resources (tags on VPCs, Subnets, ASGs, and Images)
INHERIT_TAGS = env(
  'INHERIT_TAGS',
  default=['env:', 'opt:'],
  cast=list,
  subcast=str
  )

# The role tag is used to generate hostnames for the instance, limn uses
# the value of the first tag found to set the first portion of the hostname
ROLE_TAGS = env(
  'ROLE_TAGS',
  default=['opt:cluster', 'clusterid', 'elasticbeanstalk:environment-name'],
  cast=list,
  subcast=str
  )

logger = logging.getLogger()
FORMAT = (
  '%(asctime)s.%(msecs)3d (Z) %(aws_request_id)s '
  '%(levelname)s:%(name)s:%(lineno)d:%(funcName)s:%(message)s\n'
)
datefmt = '%Y-%m-%d %H:%M:%S'
for hand in [h for h in logger.handlers]:
  hand.setFormatter(logging.Formatter(FORMAT, datefmt=datefmt))
logger.setLevel(getattr(logging, LOG_LEVEL.upper()))
# override log level for boto3/botocore. these get spammy.
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)

# Log our runtime config
logger.info((
  'Invoked with config: '
  'AWS_ASSUME_ROLES={}, '
  'LOG_LEVEL={}, '
  'INHERIT_TAGS={}, '
  'ROLE_TAGS={}').format(
    json.dumps(AWS_ASSUME_ROLES),
    json.dumps(LOG_LEVEL),
    json.dumps(INHERIT_TAGS),
    json.dumps(ROLE_TAGS)))

# http://stackoverflow.com/a/32225623
json.JSONEncoder.default = lambda self, obj: (obj.isoformat() if isinstance(obj, datetime.datetime) else None)

# https://www.andreas-jung.com/contents/a-python-decorator-for-measuring-the-execution-time-of-methods
def timeit(method):
  def timed(*args, **kw):
    ts = time.time()
    result = method(*args, **kw)
    te = time.time()

    logger.debug('%2.4f:%r(%r, %r)' % (te - ts, method.__name__, args, kw))
    return result
  return timed


@timeit
def assume_role(role_arn):
  if role_arn:
    sts = boto3.client('sts')
    try:
      return sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='limn',
        DurationSeconds=3600
      )['Credentials']
    except botocore.exceptions.ClientError as e:
      return e.response
  else:
    return None


@timeit
def boto3_client(service, region, creds=None):
  if creds:
    try:
      return boto3.client(
        service,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region
      )
    except botocore.exceptions.ClientError as e:
      return e.response
  else:
    return boto3.client(service, region_name=region)


@timeit
def describe_instance(instanceId, ec2_client):
  return ec2_client.describe_instances(
    InstanceIds=[instanceId]
  )['Reservations'][0]['Instances'][0]


# Generate a human-readable name in the format of "adjectiveanimal"
def human_name(instance_id):
  # Load animals and adjectives to generate human-readable unique names
  with open('assets/animals.txt') as f:
    ANIMALS = f.readlines()
  with open('assets/adjectives.txt') as f:
    ADJECTIVES = f.readlines()

  offset = int(hashlib.md5(instance_id.encode()).hexdigest(), 16)
  name = "{}{}".format(
    ADJECTIVES[offset % len(ADJECTIVES) - 1].rstrip(),
    ANIMALS[offset % len(ANIMALS) - 1].rstrip()
  )
  return name

class Instance:
  @timeit
  def __init__(self, accountId, region, instanceId):
    logger.debug('Looking up instance: {}, {}, {}'.format(accountId, region, instanceId))
    self.availabilityZone = None
    self.accountId = accountId
    self.region = region
    self.instanceId = instanceId
    self.instanceType = None
    self.imageId = None
    self.subnetId = None
    self.vpcId = None
    hostnames = []

    # If the account exists in AWS_ASSUME_ROLES, attempt to get sts credentials
    assume_role_arn = next((
      arn for arn in AWS_ASSUME_ROLES if arn.startswith(
        "arn:aws:iam::{}:".format(accountId)
      )
    ), None)
    assume_role_creds = assume_role(assume_role_arn)

    asg = boto3_client('autoscaling', region, assume_role_creds)
    ec2 = boto3_client('ec2', region, assume_role_creds)

    try:
      instance = describe_instance(instanceId, ec2)
      self.availabilityZone = instance['Placement']['AvailabilityZone']
      self.imageId = instance['ImageId']
      self.instanceType = instance['InstanceType']
      self.subnetId = instance['SubnetId']
      self.vpcId = instance['VpcId']

      # Add hostnames
      hostnames.append(self.instanceId)
      hostnames.append(instance.get('PublicDnsName'))
      hostnames.append(instance.get('PublicIpAddress'))
      hostnames.append(instance.get('PrivateDnsName'))
      hostnames.append(instance.get('PrivateIpAddress'))
    except botocore.exceptions.ClientError as e:
      logger.error("could not describe_instance({}): {}".format(instanceId, e.response))

    self.tags = self._get_tags(asg, ec2)
    self.dhcpDomainName = self._dhcpDomainName(ec2)
    hostnames.append(self._human_hostname())

    self.hostnames = filter(bool, hostnames)

    return None

  @timeit
  def _get_tags(self, asg, ec2):
    resources = [self.imageId, self.instanceId, self.subnetId, self.vpcId]
    try:
      aws_tags = ec2.describe_tags(
        Filters=[{
          'Name': 'resource-id',
          'Values': filter(bool, resources)
        }]
      )['Tags']
    except botocore.exceptions.ClientError as e:
      return e.response

    # If the instance is in an ASG, load the ASG tags set to 'propagate'.
    # This is to work around a race condition since launching instances from an
    # ASG and tagging operations don't happen at the same time.
    try:
      group = asg.describe_auto_scaling_instances(
        InstanceIds=[self.instanceId]
      )['AutoScalingInstances'][0]['AutoScalingGroupName']
      aws_tags.extend(
        asg.describe_tags(
          Filters=[
            {'Name': 'auto-scaling-group', 'Values': [group]},
            {'Name': 'propagate-at-launch', 'Values': ['true']}
          ]
        )['Tags']
      )
    except:
      pass

    # Override the EC2 instance tags in order of parent resource relationship
    tags = {}
    for resource_type in ('image', 'vpc', 'subnet', 'auto-scaling-group', 'instance'):
      for t in aws_tags:
        if t['ResourceType'] == resource_type:
          # add all tags from the instance
          if resource_type == 'instance':
            tags[t['Key']] = t['Value']
          # add INHERIT_TAGS from parent resources
          elif any([t['Key'].lower().startswith(match.lower()) for match in INHERIT_TAGS]):
            tags[t['Key']] = t['Value']
    return tags

  @timeit
  def _dhcpDomainName(self, ec2):
    # Load the DHCP Domain Name associated with the instance's VPC
    try:
      dhcp_options_id = ec2.describe_vpcs(
        VpcIds=[self.vpcId]
      )['Vpcs'][0]['DhcpOptionsId']

      dhcp_configurations = ec2.describe_dhcp_options(
        DhcpOptionsIds=[dhcp_options_id]
      )['DhcpOptions'][0]['DhcpConfigurations']

      return filter(
        lambda c: c['Key'] == 'domain-name',
        dhcp_configurations
      )[0]['Values'][0]['Value']
    except:
      pass
    return None

  # Generate a hostname based on the ec2 instance metadata. Defaults to
  # existing 'Name' tag, appending 'dhcpDomainName' if found.
  @timeit
  def _human_hostname(self):
    tags = dict((k.lower(), v) for k, v in self.tags.iteritems())
    # Get the role id by searching the instance tags
    role = next(
      (tags[k] for k in tags.keys() if k in map(str.lower, ROLE_TAGS)),
      'noroledef'
    )
    # Add the human_name fqdn
    hostname = "{}-{}-{}".format(
      role,
      self.instanceId.replace('i-', ''),
      human_name(self.instanceId)
    ).strip('.')

    if self.dhcpDomainName:
      hostname += ".{}".format(self.dhcpDomainName)

    return hostname

  def __repr__(self):
    return "Instance: {}".format(self.instanceId)


def main(event, context):
  response = {
    "statusCode": 200,
    "body": 'Usage: curl -XPOST --data-urlencode "identity=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/pkcs7)" https://limn.company.com/'
  }
  logger.debug("event: {}".format(json.dumps(event)))
  if 'body' in event:
    identity = event['body']
    if identity.startswith('identity='):
      identity = identity[9:]
    try:
      identity = urllib.unquote(identity).decode('utf8')
      trusted_doc = awstrust.verify_pkcs7(identity)
      instance = Instance(
        trusted_doc['accountId'],
        trusted_doc['region'],
        trusted_doc['instanceId'])
      response['body'] = json.dumps(instance.__dict__)
    except Exception as e:
      response['statusCode'] = 401
      response['body'] = "Error: {}".format(e)
      raise
  logger.info("response: {}".format(json.dumps(response)))
  return response
