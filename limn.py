import os
import sys
import functools
import json
import boto3
import datetime
import time

from botocore.exceptions import ClientError

import hashlib
from M2Crypto import SMIME, X509, BIO
from M2Crypto.SMIME import PKCS7_Error

from pymemcache.client.base import Client as MemcacheClient
from envparse import env

from requests.structures import CaseInsensitiveDict

from flask import (
  Flask,
  request
)


# INHERIT_TAGS is a space-separated list of prefixes allowed to be inherited
# by parent resources (tags on VPCs, Subnets, ASGs, and Images)
INHERIT_TAGS = env('INHERIT_TAGS', default='env: opt:').split()

ROLE_TAGS = env(
  'ROLE_TAGS',
  default='opt:cluster clusterid elasticbeanstalk:environment-name'
).split()

MEMCACHE_HOST = env('MEMCACHE_HOST', default=None)
MEMCACHE_PORT = env('MEMCACHE_PORT', cast=int, default=11211)

AWS_ASSUME_ROLES = env('AWS_ASSUME_ROLES', default="").split()

app = Flask(__name__)

# Load animals and adjectives to generate human-readable unique names
with open('assets/animals.txt') as f:
  ANIMALS = f.readlines()
with open('assets/adjectives.txt') as f:
  ADJECTIVES = f.readlines()

if MEMCACHE_HOST:
  memcache = MemcacheClient((MEMCACHE_HOST, MEMCACHE_PORT))

# http://stackoverflow.com/a/32225623
json.JSONEncoder.default = lambda self, obj: (obj.isoformat() if isinstance(obj, datetime.datetime) else None)


# https://gist.github.com/abahgat/1395810
def cached(timeout=600):
  """
  Decorator that caches the result of a method for the specified time in seconds.

  Use it as:

    @cached(timeout=1200)
    def functionToCache(arguments):
      ...

  """
  def decorator(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
      if MEMCACHE_HOST:
        key = hashlib.md5("{}{}{}".format(
                                      function.__name__,
                                      str(args),
                                      str(kwargs))).hexdigest()
        value = memcache.get(key)
        print('{}: Cache lookup for {}, found? {}'.format(time.time(), key, value is not None))
        if not value:
          value = json.dumps(function(*args, **kwargs))
          memcache.set(key, value, expire=timeout)
      else:
        value = json.dumps(function(*args, **kwargs))
      return json.loads(value)
    return wrapper
  return decorator


# https://www.andreas-jung.com/contents/a-python-decorator-for-measuring-the-execution-time-of-methods
def timeit(method):
  def timed(*args, **kw):
    ts = time.time()
    result = method(*args, **kw)
    te = time.time()

    print '%2.4f: %r (%r, %r)' % \
      (te - ts, method.__name__, args, kw)
    return result

  return timed


# Verify a PKCS7 signed instance identity document. This is a simple way to
# authenticate an EC2 instance is who it claims to be.
@timeit
def verify_pkcs7(pkcs7):
  pkcs7 = "-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----".format(pkcs7)
  s = SMIME.SMIME()

  sk = X509.X509_Stack()
  sk.push(X509.load_cert('assets/aws_public_certificate.pem'))
  s.set_x509_stack(sk)

  st = X509.X509_Store()
  st.load_info('assets/aws_public_certificate.pem')
  s.set_x509_store(st)

  p7bio = BIO.MemoryBuffer(pkcs7)
  p7 = SMIME.load_pkcs7_bio(p7bio)

  try:
    return json.loads(s.verify(p7))
  except SMIME.PKCS7_Error as e:
    raise Exception("Could not verify identity document:", e)


# Request token valid for 60 minutes, cache for 59 minutes
@timeit
@cached(3540)
def assume_role(role_arn):
  sts = boto3.client('sts')

  try:
    credentials = sts.assume_role(
      RoleArn=role_arn,
      RoleSessionName='limn',
      DurationSeconds=3600
    )['Credentials']
  except ClientError as e:
    return e.response

  print("Returning credentials: {}".format(credentials))

  return credentials


# Generate a human-readable name in the format of "adjectiveanimal"
@timeit
def human_name(instance_id):
  offset = int(hashlib.md5(instance_id.encode()).hexdigest(), 16)
  name = "{}{}".format(
    ADJECTIVES[offset % len(ADJECTIVES) - 1].rstrip(),
    ANIMALS[offset % len(ANIMALS) - 1].rstrip()
  )
  return name


# Fetch tags and other metadata about an instance in an account
@timeit
@cached(60)
def describe_instance(instance_document):

  print("Searching for role matching: {} in roles: {}".format(instance_document['accountId'], AWS_ASSUME_ROLES))
  assume_role_arn = next(
    (arn for arn in AWS_ASSUME_ROLES if arn.startswith(
      "arn:aws:iam::{}:".format(instance_document['accountId']))),
    None)
  if assume_role_arn:
    print("found role: {}".format(assume_role_arn))

  try:
    creds = assume_role(assume_role_arn)
    ec2 = boto3.client(
      'ec2',
      aws_access_key_id=creds['AccessKeyId'],
      aws_secret_access_key=creds['SecretAccessKey'],
      aws_session_token=creds['SessionToken'],
      region_name=instance_document['region']
    )
    asg = boto3.client(
      'autoscaling',
      aws_access_key_id=creds['AccessKeyId'],
      aws_secret_access_key=creds['SecretAccessKey'],
      aws_session_token=creds['SessionToken'],
      region_name=instance_document['region']
    )
  except:
    ec2 = boto3.client('ec2', region_name=instance_document['region'])
    asg = boto3.client('autoscaling', region_name=instance_document['region'])

  try:
    instance = ec2.describe_instances(
      InstanceIds=[
        instance_document['instanceId']
      ]
    )['Reservations'][0]['Instances'][0]

    aws_tags = ec2.describe_tags(
        Filters=[
          {
            'Name': 'resource-id',
            'Values': [
              instance['ImageId'],
              instance['InstanceId'],
              instance['SubnetId'],
              instance['VpcId']
            ]
          }
        ]
      )['Tags']
  except ClientError as e:
    return e.response

  # If the instance is in an ASG, load the ASG tags set to 'propagate'.
  # This is to work around a race condition since launching instances from an
  # ASG and tagging 'propagate-at-launch' tags don't happen at the same time.
  try:
    group = asg.describe_auto_scaling_instances(
        InstanceIds=[
          instance_document['instanceId']
        ]
      )['AutoScalingInstances'][0]['AutoScalingGroupName']
    aws_tags.extend(
        asg.describe_tags(
          Filters=[
            {
              'Name': 'auto-scaling-group',
              'Values': [
                group
              ]
            },
            {
              'Name': 'propagate-at-launch',
              'Values': [
                'true'
              ]
            }
          ]
        )['Tags']
      )
  except:
    pass

  # Override the EC2 instance tags in order of parent resource relationship
  # Exclude tags that don't start with values from INHERIT_TAGS
  override_tags = {}
  for resource_type in ('image', 'vpc', 'subnet', 'auto-scaling-group', 'instance'):
    for t in aws_tags:
      if t['ResourceType'] == resource_type:
        if resource_type == 'instance':
          override_tags[t['Key']] = t['Value']
        elif any([t['Key'].lower().startswith(match.lower()) for match in INHERIT_TAGS]):
          override_tags[t['Key']] = t['Value']
  instance_document['tags'] = override_tags

  # Load the DHCP Domain Name associated with the instance's VPC
  try:
    dhcp_options_id = ec2.describe_vpcs(
      VpcIds=[instance['VpcId']]
    )['Vpcs'][0]['DhcpOptionsId']

    dhcp_configurations = ec2.describe_dhcp_options(
      DhcpOptionsIds=[dhcp_options_id]
    )['DhcpOptions'][0]['DhcpConfigurations']

    dhcp_domain_name = filter(
      lambda c: c['Key'] == 'domain-name',
      dhcp_configurations
    )[0]['Values'][0]['Value']

    instance_document['dhcpDomainName'] = dhcp_domain_name
  except:
    pass

  instance_document['hostnames'] = generate_hostnames(instance_document)

  return dict(instance_document)


# Generate a hostname based on the ec2 instance metadata. Defaults to
# existing 'Name' tag, appending 'dhcpDomainName' if found.
@timeit
def generate_hostnames(instance_document):
  instance_tags = CaseInsensitiveDict(instance_document['tags'])

  # Get the role id by searching the instance tags
  role = next(
    (instance_tags[k] for k in instance_tags.keys() if k.lower() in map(str.lower, ROLE_TAGS)),
    'noroledef'
  )

  hostnames = []

  # Return the 'Name' tag, or generate a new one
  if 'Name' in instance_tags:
    hostnames.append(instance_tags['name'])

  hostnames.append("{}-{}-{}".format(
    role,
    instance_document['instanceId'].replace('i-', ''),
    human_name(instance_document['instanceId'])
  ).strip('.'))

  return hostnames


# Lambda function entrypoint
@app.route("/", methods=['GET', 'POST'])
def main():
  if request.method == 'POST':
    try:
      instance_document = CaseInsensitiveDict(
        (k, v) for k, v in verify_pkcs7(
          request.form['identity']
        ).iteritems() if v
      )
    except PKCS7_Error as e:
      return "Error: {}".format(e), 401

    if instance_document:
      instance = describe_instance(instance_document)
      return json.dumps(instance)

  return 'bad request'


if __name__ == "__main__":
  port = env('PORT', cast=int, default=5000)
  host = env('LISTEN', default='0.0.0.0')
  if port == 5000:
    app.debug = True
  app.run(host=host, port=port)
