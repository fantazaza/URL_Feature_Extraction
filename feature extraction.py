
from bs4 import BeautifulSoup
import requests
import urllib
import bs4
import re
import socket
import whois
import ssl
from datetime import datetime, timedelta
import time
from googlesearch import search
import pandas as pd
import csv
import dns.resolver
# This import is needed only when you run this file in isolation.
import sys
import certifi
from patterns import *
from url_utils import extract_data

# from utils import generate_data_set

url_data = pd.read_csv('.csv')
urls = url_data['url']
extract_urls = []
for i, url in enumerate(urls, 1):
    extract_urls.append(extract_data(url))
    print(i ,"/",len(urls), extract_data(url))
    columns = ['Having_IP_Address','Shortening_Service','Having_At_Symbol','Double_slash_redirecting',
    'Prefix_Suffix','Having_Sub_Domain','SSLfinal_state','Domain_registeration_length','Favicon'
    ,'Links_pointing_to_page','Age_of_domain','Check_url_in_csv','DNS_Record']#<----- You can add class in columns.
    df = pd.DataFrame(extract_urls, columns=columns)
    result = pd.concat([url_data, df], axis=1)
    result.to_csv('extract_urls.csv', index=False)
