#!/usr/bin/env python3

import argparse
import dns.resolver
import ipaddress
import requests
import csv
import re
from datetime import datetime
from collections import OrderedDict

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--domain', type=str, required=True, help='Domain to test.')
args = parser.parse_args()

# Add excluded infrastructure domains here.
excluded_domains = {'amazonses.com'}

def download_aws_ip_ranges():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to download AWS IP ranges. Status code: {response.status_code}")

def parse_record(record, domain):
    parts = record.split()
    for part in parts:
        if part.startswith(('include:', 'redirect=')):
        #if part.startswith('include:'):
            parts2 = re.split('[:=]', part)
            included_domain = parts2[1] if len(parts) > 1 else None
            #included_domain = part.split(':')[1]
            yield from get_spf_ips(included_domain)
        elif (
            part.startswith('ip4:') or 
            part.startswith('+ip4:') or 
            part.startswith('ip6:') or 
            part.startswith('+ip6:') or 
            part.startswith('a:') or 
            part == 'a' or 
            part.startswith('mx') or 
            part.startswith('+mx') or
            part == 'mx'
        ):
            yield part, domain

def get_spf_ips(domain):
    for record_type in ['TXT', 'SPF']:
        try:
            full_record = ""
            count = 0
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_string = txt_string.decode('utf-8')
                    if (
                        txt_string.startswith('v=spf1') or 
                        txt_string.startswith('v=spf2.0') or
                        txt_string.startswith('spf2.0') or 
                        count > 0
                    ):
                        if "redirect" not in txt_string:
                            full_record += txt_string
                            count += 1
                        else:
                            full_record = txt_string
            yield from parse_record(full_record, domain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue

def resolve_hostname_to_ips(hostname):
    ipv4_addresses = set()
    ipv6_addresses = set()

    def resolve_records(hostname, record_type):
        try:
            for ip in dns.resolver.resolve(hostname, record_type):
                ipv4_addresses.add(ip.to_text())
        except:
            #print(f"Error resolving {record_type} records for {hostname}. Moving on.")
            pass

    try:
        # Check for CNAME records
        cname_response = dns.resolver.resolve(hostname, 'CNAME')
        for cname in cname_response:
            cname_target = cname.target.to_text()
            print(f"{hostname} is an alias for {cname_target}")
            resolve_records(cname_target, 'A')
            resolve_records(cname_target, 'AAAA')

    except dns.resolver.NoAnswer:
        # If no CNAME records are found, resolve A and AAAA records directly
        resolve_records(hostname, 'A')
        resolve_records(hostname, 'AAAA')

    except dns.resolver.NXDOMAIN:
        print(f"The domain {hostname} does not exist.")
    except dns.exception.DNSException as e:
        print(f"An error occurred: {e}")

    return ipv4_addresses, ipv6_addresses

def process_domain(domain):
    ipv4_set = set()
    ipv4_cidr_set = set()
    ipv6_set = set()

    for record_entry, host in get_spf_ips(domain):
        if record_entry.startswith(('ip4:', '+ip4')):
            ip = record_entry.split(':')[1]
            if '/' in ip:  # CIDR block
                ipv4_cidr_set.add(ip)
            else:  # Single IP
                ipv4_set.add(ip)
        elif record_entry.startswith(('ip6:', '+ip6')):
            ipv6 = record_entry[4:]
            ipv6_set.add(ipv6)
        elif record_entry.startswith('a:') or record_entry == 'a':
            hostname = host if record_entry == 'a' else record_entry.split(':')[1]
            ipv4s, ipv6s = resolve_hostname_to_ips(hostname)
            ipv4_set.update(ipv4s)
            ipv6_set.update(ipv6s)
        elif record_entry.startswith(('mx', '+mx')) or record_entry == 'mx':
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    ipv4s, ipv6s = resolve_hostname_to_ips(mx.exchange.to_text())
                    ipv4_set.update(ipv4s)
                    ipv6_set.update(ipv6s)
            except dns.resolver.NoAnswer:
                pass

    return ipv4_set, ipv4_cidr_set, ipv6_set

def explode_cidr(cidr_block):
    network = ipaddress.ip_network(cidr_block, strict=False)
    return [str(ip) for ip in network]

def ip_in_range(ip, ranges):
    if '/' in ip:  # CIDR block
        network1 = ipaddress.ip_network(ip, strict=False)
        for range in ranges:
            network2 = ipaddress.ip_network(range, strict=False)
            if network1.subnet_of(network2):
                return True
        return False

    else: # IP 
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range in ranges:
                if ip_obj in ipaddress.ip_network(range):
                    return True
            return False
        except:
            return False

def write_to_csv(data, domain, ids):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    filename = f"{domain}-{ids}-{timestamp}.csv"
    headers = ['ip', 'service', 'region']
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)

        # Write the header
        writer.writeheader()

        # Write the data rows
        for row in data:
            writer.writerow(row)

def main():
    aws_ips_for_domain = []
    exclude_ipv4 = set()
    exclude_cidr = set()
    exclude_ipv6 = set()
    for domain in excluded_domains:
        a, b, c = process_domain(domain)
        exclude_ipv4.update(a)
        exclude_cidr.update(b)
        exclude_ipv6.update(c)

    domain_name = args.domain
    ipv4_addresses, ipv4_cidr, ipv6_addresses = process_domain(domain_name)
    aws_json_object = download_aws_ip_ranges()
    aws_ipv4_ranges = [(item['ip_prefix'], item['service'], item['region']) for item in aws_json_object['prefixes']]
    
    print(f"Total IPv4 Addresses to check: {len(ipv4_addresses)}")
    print(f"Total IPv4 CIDR Blocks to check: {len(ipv4_cidr)}")

    # Check Indvidual IPs
    count = 0
    for ip in ipv4_addresses:
        count = count + 1
        if count % 100 == 0:
            print(f"Checking {count} of {len(ipv4_addresses)}")

        for ip_prefix, service, region in aws_ipv4_ranges:
            if ip_in_range(ip, [ip_prefix]) and ip not in exclude_ipv4:
                aws_ips_for_domain.append({'ip': ip, 'service': service, 'region': region})
                print(f"IP: {ip}\t\tRegion: {region}")
                break

    # Output to CSV
    write_to_csv(aws_ips_for_domain, domain_name, "ip")

    # Check CIDR Blocks 
    count = 0
    for cidr_block in ipv4_cidr:
        count = count + 1
        if count % 100 == 0:
            print(f"Checking {count} of {len(ipv4_cidr)}")

        for ip_prefix, service, region in aws_ipv4_ranges:
            if ip_in_range(cidr_block, [ip_prefix]) and cidr_block not in exclude_cidr:
                temp_aws_ips = set()
                temp_aws_ips.update(explode_cidr(cidr_block))
                for ip in temp_aws_ips:
                    aws_ips_for_domain.append({'ip': ip, 'service': service, 'region': region})
                print(f"CIDR: {cidr_block}\t\tRegion: {region}")
                break

    print(f"Total AWS IPv4 Addresses: {len(aws_ips_for_domain)}")

    # Output to CSV
    write_to_csv(aws_ips_for_domain, domain_name, "cidr")

if __name__ == "__main__":
    main()
