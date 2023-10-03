from patterns import *
from dns import resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
import ssl
import urllib
import bs4
import re
import socket
import whois
import time
import pandas as pd
import csv
import dns.resolver
import sys
import requests
import certifi

# Calculates number of months
#!Date&Time
def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month
#!1
def having_ip_address(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1

#!2
def shortening_service(url):
    match = re.search(shortening_services, url)
    return 1 if match else -1

#!3
def having_at_symbol(url):
    match = re.search('@', url)
    return 1 if match else -1

#!4
def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return 1 if last_double_slash > 6 else -1
#!5
def prefix_suffix(domain):
    match = re.search('-', domain)
    return 1 if match else -1
#!6
def having_sub_domain(url):
    if having_ip_address(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    else:
        return -1
# #!7
def SSLfinal_state(hostname):
    try:
        # Create SSL context
        context = ssl.create_default_context(cafile=certifi.where())

        # Check SSL certificate
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                # Check if SSL certificate is valid for more than one year
                if expiry_date > datetime.now() + timedelta(days=365):
                    return -1
                else:
                    return 1
    except ssl.SSLError as e:
        return 0
    except Exception as e:
        return 0
def SSLfinal_state_with_timeout(hostname, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = SSLfinal_state(hostname)
        if result != 0:  # If not an error, return the result
            return result
    return 0  # Return 0 if the function times out
#!8
def domain_registration_length(url):
    try:
        # Use whois.whois() to retrieve WHOIS information of the domain
        domain_info = whois.whois(url)
        
        # Check if expiration date is available in the WHOIS data
        if domain_info.expiration_date:
            # If expiration_date is a list, take the first element
            expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date

            today = datetime.today()
            registration_length = abs((expiration_date - today).days)

            if registration_length / 365 > 1:
                return 1  # More than 1 year
            else:
                return -1   # Less than or equal to 1 year
        else:
            return 0  # Error or no expiration date
    except Exception as e:
        return 0 

#!9
def favicon(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find the favicon URL from the HTML
        favicon_url = None
        link_tags = soup.find_all('link', rel='icon')
        for tag in link_tags:
            if 'href' in tag.attrs:
                favicon_url = tag['href']
                break
        return 1 if favicon_url else -1
    except requests.exceptions.Timeout:
        print("Request timed out.")
        return 0
    except Exception as e:
        print("An error occurred:", e)
        return 0
#!10
def links_pointing_to_page(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        number_of_links = len(soup.find_all('a', href=True))

        if number_of_links == 0:
            return -1
        elif number_of_links <= 2:
            return 0
        else:
            return 1

    except Exception as e:
        print("Error:", e)
        return 0
#!11
def age_of_domain(url):
    try:
        w = whois.whois(url)
        if w.creation_date is None or w.expiration_date is None:
            return 0

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        current_date = datetime.now()
        age_in_months = diff_month(current_date, creation_date)

        if age_in_months < 6:
            return 1
        else:
            return -1

    except Exception as e:
        print("Error:", e)
        return 0
#!12
def dns_rec(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'NS')
        if answers:
            return -1  # มีข้อมูล NS
        else:
            return 1   # ไม่มีข้อมูล NS
    except dns.resolver.NXDOMAIN:
        return 1  # ไม่มีข้อมูล NS
    except Exception as e:
        return 1
#!13  
def read_csv(csv_file_path):
    urls = []
    with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            if row:
                urls.extend(row)
    return urls
def check_url_in_csv(csv_file_path, url):
    urls = read_csv(csv_file_path)
    return 1 if url in urls else -1
csv_file_path = 'phishing_verified_online.csv'
#!Get hostname
def get_hostname_from_url(url):
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    pattern = "https://|http://|www.|https://www.|http://www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname
#!Extract Data
def extract_data(url):
    status = []
    hostname = get_hostname_from_url(url)
 #!1
    status.append(having_ip_address(url))
 #!2
    status.append(shortening_service(url))
 #!3
    status.append(having_at_symbol(url))
 #!4
    status.append(double_slash_redirecting(url))
 #!5
    status.append(prefix_suffix(hostname))
 #!6
    status.append(having_sub_domain(url))
 #!7
    status.append(SSLfinal_state_with_timeout(hostname, timeout=10))
 #!8
    status.append(domain_registration_length(url))
 #!9
    status.append(favicon(url))
 #!10
    status.append(links_pointing_to_page(url))
 #!11
    status.append(age_of_domain(url))
 #!12
    status.append(check_url_in_csv(csv_file_path,url))
 #!13
    status.append(dns_rec(hostname))
 #!Check array
    print(status)
    return status
   

