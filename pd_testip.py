#!/usr/bin/env python3

import argparse
import boto3
from botocore.exceptions import ClientError
import csv

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--log', nargs='?', type=str, required=True, help='Log file to parse and attempt to grab IPs.')
args = parser.parse_args()

def allocate_address(allowed_regions, region_name, domain, address):
    c2_client = None

    # We do not attempt GLOBAL IPs, Gov Cloud IPs, or any region we do not have perms
    #if region_name != 'GLOBAL' and "us-gov" not in region_name:
    if region_name in allowed_regions:
        ec2_client = boto3.client('ec2', region_name=region_name)
    else:
        return f"{region_name} is not supported."

    # Allocate the address
    try:
        allocation = ec2_client.allocate_address(Domain=domain, Address=address)
        return allocation
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidAddress.NotFound':
            return f"{address} is not available."
        elif error_code == 'AuthFailure':
            return f"Auth error for this IP/region. {region_name} may not be supported."
        else:
            print(f"An error occurred: {e}")
        return None

def read_csv_to_dict():
    data = []
    filename = args.log

    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                data.append(row)
    except:
        print(f"Could not open file {args.log}.")

    return data

def main():
    aws_data = read_csv_to_dict()

    # Set up EC2 boto client
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_regions()
    allowed_regions = {region['RegionName'] for region in response['Regions']}

    for ip in aws_data:
        allocation_result = allocate_address(allowed_regions, ip['region'], 'vpc', ip['ip'])
        print(allocation_result)

if __name__ == "__main__":
    main()