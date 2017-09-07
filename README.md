# limn

Limn is a reflective description service, providing a secure way to discover
tags, hostnames, and other metadata about an EC2 Instance. It's useful for
bootstrapping configuration and platform automation.

## Deployment

Limn is a [serverless](https://serverless.com/) app for AWS Lambda. It requires
some python packages (such as M2Crypto) which aren't available in the base
[Lambda Execution Environment](http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html).
The included `build.sh` uses Docker to compile dependencies so they are
compatible with the Lambda environment, installing them under the `vendored/`
directory.

```console
$ ./build.sh
```

Modify the included [serverless.yml](serverless.yml) as necessary to support
your environment.

#### Cross-Account Support

Limn supports cross-account resource description using `sts:AssumeRole`. To
enable this feature you should update the `iamRoleStatements` and `environment`
in `serverless.yml` to include the cross-account roles limn can assume:

```yaml
provider:
  name: aws
  iamRoleStatements:
    - Effect: "Allow"
      Action:
        - "sts:AssumeRole"
      Resource:
        - "arn:aws:iam::123456789012:role/limn"
        - "arn:aws:iam::345678901234:role/limn"
        - "arn:aws:iam::567890123456:role/limn"
  environment:
    AWS_ASSUME_ROLES: >
      arn:aws:iam::123456789012:role/limn
      arn:aws:iam::345678901234:role/limn
      arn:aws:iam::567890123456:role/limn
```

## Usage

### Describing Yourself

The limn API is simple. `POST` your EC2 instance's pkcs7 signed
[instance identity document](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html) against the limn server. If the signature is valid limn responds with the decoded identity document and any additional
resources it discovers (`tags`, `hostnames`, `dhcpDomainName`, etc).

```console
(~)$ PKCS7="$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/pkcs7)"
(~)$ curl -s -XPOST --data-urlencode "$PKCS7" https://limn.server.url/|jq '.'
{
  "availabilityZone": "us-west-2c",
  "tags": {
    "Name": "test-089ffe0ecf7fcc169-swankymuskrat",
    "ClusterId": "test",
    "env:datacenter": "example-usw2",
    "aws:autoscaling:groupName": "test-v000",
  },
  "instanceId": "i-089ffe0ecf7fcc169",
  "region": "us-west-2",
  "dhcpDomainName": "example-usw2.mydomain.com",
  "imageId": "ami-a03facc8",
  "vpcId": "vpc-fd43b248",
  "subnetId": "subnet-9036b7d0",
  "instanceType": "t2.small",
  "hostnames": [
    "i-089ffe0ecf7fcc169",
    "ip-10-21-32-193.us-west-2.compute.internal",
    "10.21.32.193",
    "test-089ffe0ecf7fcc169-swankymuskrat.example-usw2.mydomain.com"
  ],
  "accountId": "123456789012"
```

## Configuration <a name="configuration" href="#configuration">:link:</a>

Limn configuration is passed as environment variables. Multiple values should
take the form of space-separated strings.

| var | defaults | cast | description |
|-----|----------|------|-------------|
| `AWS_ASSUME_ROLES` | `(empty string)` | `str.split()` | List of roles limn can assume to lookup resources in different accounts. If this is not set, or limn can't find a configured role associated with the instance's `accountId` it will attempt to use [boto3 credentials](http://boto3.readthedocs.io/en/latest/guide/configuration.html). |
| `INHERIT_TAGS` | `env:` `opt:` | `str.split()` | Whitelist of tag prefixes allowed to be inherited from parent resources. See [Tag Discovery](#tag-discovery) for details. |
| `ROLE_TAGS` | `opt:cluster` `clusterid` `elasticbeanstalk:environment-name` | `str.split()` | Used for dynamic hostname generation. See [Hostname Discovery](#hostname-discovery) for details. |


### IAM Policy

Limn needs the following IAM permissions to run:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeDhcpOptions",
                "ec2:DescribeInstances",
                "ec2:DescribeTags",
                "ec2:DescribeVpcs",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeTags"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

### Serving Multiple AWS Accounts with AssumeRole

To enable cross-account lookups with limn, update its IAM policy to include an
appropriate `sts:AssumeRole` statement for each account (including the one where
your limn server is running):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {"": "..."},
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": [
              "arn:aws:iam::<primary-account-number>:role/limn",
              "arn:aws:iam::<secondary-account-number>:role/limn"
            ]
        }
    ]
}
```

For each role limn can assume, attach a Trust Relationship to enable
cross-account access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<primary-account-number>:role/limn"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Configure the environment variable `AWS_ASSUME_ROLES` with the Role ARNs for
each account as a space-separated string.

## Tag Discovery <a name="tag-discovery" href="#tag-discovery">:link:</a>

Limn uses a hierarchical override to resolve tags for EC2 instances. If the tags
for any parent resource match a prefix defined by `INHERIT_TAGS` they're
returned as part of the instance description.

Inherited tags are discovered and overridden in the following order: `image`,
`vpc`, `subnet`, `auto-scaling-group`, and finally the `instance` itself. The
following graph shows tag inheritance and overriding in action. Instances in
each subnet inherit tags from their parent subnet, and their subnet's parent
vpc.

![limn tag inheritance](assets/limn-tag-inheritance.png)

The tags set against resources are:

| resource  | tag | value |
|-----------|-----|-------|
| `vpc` | `env:CASSH_URL` | `cassh.default-usw2` |
| `vpc` | `env:CONSUL_DC` | `usw2` |
| `subnet-prod` | `env:CASSH_URL` | `cassh.prod-usw2` |
| `subnet-stage` | `env:CONSUL_DC` | `staging-usw2` |

The tags resolve with inheritance as:

| resource  | tag | value |
|-----------|-----|-------|
| `prod-instance(s)` | `env:CONSUL_DC` | `usw2` |
| | `env:CASSH_URL` | `cassh.prod-usw2` |
| `stage-instance(s)` | `env:CONSUL_DC` | `staging-usw2` |
| | `env:CASSH_URL` | `cassh.default-usw2` |

## Hostname Discovery <a name="hostname-discovery" href="#hostname-discovery">:link:</a>

Limn provides an opinionated hostname generator returning the instance's 'Name'
tag (if set), and a programmatic hostname with the format:

    <role>-<instance_id>-<adjective><animal>

 - `role` is discovered from the first resolved instance tag matching
`ROLE_TAGS` (case insensitive). By default it looks for the
following tags in order: `opt:cluster`, `clusterid`, and
`elasticbeanstalk:environment-name`.

- `instance_id` is stripped of leading `i-`, so `i-abcdefgh` becomes `abcdefgh`.

- `adjective` and `animal` are generated from wordlists using a consistent hash
function based on the instance id.

- `vpcDhcpDomainName` is discovered from the DHCP Options attached the the VPC
associated with the instance.
