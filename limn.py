import awstrust
import boto3
import botocore
import datetime
import envparse
import flask
import functools
import hashlib
import json
import logging
import pymemcache.client.base
import time


AWS_ASSUME_ROLES = envparse.env('AWS_ASSUME_ROLES', default="").split()
# INHERIT_TAGS is a space-separated list of prefixes allowed to be inherited
# by parent resources (tags on VPCs, Subnets, ASGs, and Images)
INHERIT_TAGS = envparse.env('INHERIT_TAGS', default='env: opt:').split()
ROLE_TAGS = envparse.env(
  'ROLE_TAGS',
  default='opt:cluster clusterid elasticbeanstalk:environment-name'
).split()
LOG_LEVEL = envparse.env('LOG_LEVEL', default='info').upper()
MEMCACHE_HOST = envparse.env('MEMCACHE_HOST', default=None)
MEMCACHE_PORT = envparse.env('MEMCACHE_PORT', cast=int, default=11211)
if MEMCACHE_HOST:
  memcache = pymemcache.client.base.Client((MEMCACHE_HOST, MEMCACHE_PORT))

# Create the flask app
app = flask.Flask(__name__)
app.logger.setLevel(getattr(logging, LOG_LEVEL))


# http://stackoverflow.com/a/32225623
json.JSONEncoder.default = lambda self, obj: (obj.isoformat() if isinstance(obj, datetime.datetime) else None)


# https://www.andreas-jung.com/contents/a-python-decorator-for-measuring-the-execution-time-of-methods
def timeit(method):
  def timed(*args, **kw):
    ts = time.time()
    result = method(*args, **kw)
    te = time.time()

    app.logger.debug('%2.4f: %r (%r, %r)' % (te - ts, method.__name__, args, kw))
    return result
  return timed


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
        key = "{}{}{}".format(function.__name__, str(args), str(kwargs))
        hashkey = hashlib.md5(key).hexdigest()
        value = memcache.get(hashkey)
        app.logger.debug(
          '{}: Cache lookup for {}, found? {}'.format(
            time.time(),
            key,
            value is not None
          )
        )
        if not value:
          value = json.dumps(function(*args, **kwargs))
          memcache.set(hashkey, value, expire=timeout)
      else:
        value = json.dumps(function(*args, **kwargs))
      return json.loads(value)
    return wrapper
  return decorator


@timeit
@cached(3570)
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
    app.logger.debug('Looking up instance: {}, {}, {}'.format(accountId, region, instanceId))
    self.availabilityZone = None
    self.accountId = accountId
    self.region = region
    self.instanceId = instanceId
    self.instanceType = None
    self.imageId = None
    self.subnetId = None
    self.vpcId = None
    self.hostnames = []

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
      self.hostnames.append(self.instanceId)
      if instance['PublicDnsName']:
        self.hostnames.append(instance['PublicDnsName'])
      if instance['PublicIpAddress']:
        self.hostnames.append(instance['PublicIpAddress'])
      if instance['PrivateDnsName']:
        self.hostnames.append(instance['PrivateDnsName'])
      if instance['PrivateIpAddress']:
        self.hostnames.append(instance['PrivateIpAddress'])
    except botocore.exceptions.ClientError as e:
      app.logger.error("could not describe_instance({}): {}".format(instanceId, e.response))

    self.tags = self._get_tags(asg, ec2)
    self.dhcpDomainName = self._dhcpDomainName(ec2)
    self.hostnames.append(self._human_hostname())

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
    # Exclude tags that don't start with values from INHERIT_TAGS
    tags = {}
    for resource_type in ('image', 'vpc', 'subnet', 'auto-scaling-group', 'instance'):
      for t in aws_tags:
        if t['ResourceType'] == resource_type:
          if resource_type == 'instance':
            tags[t['Key']] = t['Value']
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


@app.route("/", methods=['GET', 'POST'])
def main():
  if flask.request.method == 'POST':
    try:
      trusted_doc = awstrust.verify_pkcs7(flask.request.form['identity'])
    except Exception as e:
      return "Error: {}".format(e), 401

    if trusted_doc:
      instance = Instance(
        trusted_doc['accountId'],
        trusted_doc['region'],
        trusted_doc['instanceId'])
      return flask.jsonify(instance.__dict__)
    else:
      return "unauthorized", 401
  else:
    return 'ok', 200


@app.route('/<accountId>/<region>/<instanceId>', methods=['GET'])
def lookup(accountId, region, instanceId):
  instance = Instance(accountId, region, instanceId)
  return flask.jsonify({'hostnames': instance.hostnames})


if __name__ == "__main__":
  port = envparse.env('PORT', cast=int, default=8080)
  host = envparse.env('LISTEN', default='0.0.0.0')
  if port == 5000:
    app.debug = True
  app.run(host=host, port=port, threaded=True)
