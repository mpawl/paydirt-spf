# Paydirt for SPF

Paydirt for SPF will help you find available AWS Elastic IP addresses in a domain's SPF record. These IPs can likely send e-mail as the target domain.

There are two componets to Paydirt for SPF. 
1. `pd_spf.py`: This script will look up and parse SPF records for the target domain.
1. `pd_testip.py`: This script ingest log files from `pd_spf.py` and attempt to acquire the Elastic IP addresses.

# Dependencies

Paydirt relies on external services:
1. Amazon AWS

An API key must be acquired for Amazon AWS. 

## Amazon AWS

The AWS CLI is required to run Pay Dirt. Amazon provides [Instructions here](https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-install.html) to install AWS CLI. 

Once installed, you must configure AWS CLI with appropriate keys and minimum configuration. The Access Key must have permissions to Allocate and Release an Elastic IP. The snipets below outline a minimum configuration. 

```
cat ~/.aws/credentials
[default]
aws_access_key_id = ...
aws_secret_access_key = ...
```

```
cat ~/.aws/config
[default]
region=us-east-1
```

# Installation

It is recommended to use a Python Virtual Environment (venv) for running Pay Dirt. Create and activate the venv as outlined below. 

```
python3 -m venv <virtual_environment_name>
source <path_to_venv>/bin/activate
```
Once the Python venv is installed and activated, install Python library dependencies. Pythong library dependencies are provided in a `requirements.txt` file. 

```
python3 -m pip install -r requirements.txt
```
# Usage

Below is the help screen for `pd_spf.py`, detailing the command line options. 

```
usage: pd_spf.py [-h] --domain DOMAIN

options:
  -h, --help       show this help message and exit
  --domain DOMAIN  Domain to test.
```

Each run of `pd_spf.py` will download the JSON file containing the list of all AWS IP addresses hosted by AWS [here](https://ip-ranges.amazonaws.com/ip-ranges.json). This file contains address blocks and the region and service the address block is assigned to. This is important because users must specify the appropriate region when when requesting a specific Elastic IP. The IP address also must not belong to an AWS infrastructure service. 


Below is the help screen for `pd_testip.py`, detailing the command line options. 

```
usage: pd_testip.py [-h] --log [LOG]

options:
  -h, --help   show this help message and exit
  --log [LOG]  Log file to parse and attempt to grab IPs.
```

# Logging

The `pd_spf.py` log files are CSVs:
* `domain-ip-YYYY-MM-DD_HH-MM-SS.csv` - This log file contains indivdual IP address entries in the SPF record. 
* `domain-cidr-YYYY-MM-DD_HH-MM-SS.csv` - This log file contains individual IP addresses and expanded CIDR block that are contained in the SPF record. This file is much longer than the IP address-only log file. Testing these IPs can take a lot more time. 

Both log files contain the same elements: 
* IP Address
* AWS service name where the IP address resides
* AWS region where the IP address resides

Below is an example log line for a MATCH:

`192.0.2.1,AMAZON,us-east-1`

# Work Flow

Meet all dependencies in the Dependencies section and meet the requirements in the Installation section. 

Run `pd_spf.py` to query a domain. The output will list the number of IP addresses and CIDR blocks found that are hosted in AWS. Below is an example of running `pd_spf.py`:

```
python pd_spf.py --domain example.com
```

If IP addresses in the SPF record are hosted in AWS, they will be populated in the following log files:
* `example.com-ip-YYYY-MM-DD_HH-MM-SS.csv`
* `example.com-cidr-YYYY-MM-DD_HH-MM-SS.csv`

Run `pd_testip.py`, feeding in one of the two log files to attempt to allocate one of the AWS Elastic IP addresses in the SPF record. The IP address log file will likely have many less entries than the CIDR log file. The CIDR log file could take some time to run through. Below is an example of running `pd_testip.py`:

```
python pd_testip.py --log example.com-ip-YYYY-MM-DD_HH-MM-SS.csv
```

# Notes

There is some IPv6 logging functionality started in `pd_spf.py`, however there are not yet Elastic IPv6 IPs and may never be. 

