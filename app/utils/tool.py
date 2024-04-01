import dns.resolver
import requests


def dns_record_lookup(domain_name, record_type):
    try:
        answers = dns.resolver.resolve(domain_name, record_type)
        result = [r.to_text() for r in answers]
        return result
    except dns.resolver.NoAnswer:
        return ["No {} record found for {}".format(record_type, domain_name)]
    except dns.resolver.NXDOMAIN:
        return ["Domain {} does not exist".format(domain_name)]
    except dns.resolver.Timeout:
        return ["Timeout occurred while performing DNS lookup"]
    except dns.exception.DNSException as e:
        return ["DNS lookup error: {}".format(str(e))]

def dnslookup(domain_name):
    url = f"https://api.hackertarget.com/dnslookup/?q={domain_name}"
    response = requests.get(url)
    if response.status_code == 200:
        output = {}
        lines = response.text.split('\n')
        for line in lines:
            if line.strip():
                if ':' in line:
                    record_type, value = line.split(':', 1)
                    record_type = record_type.strip()
                    value = value.strip()
                    if record_type in output:
                        output[record_type].append(value)
                    else:
                        output[record_type] = [value]
                else:
                    # Handle lines that do not match the expected format
                    output['Unknown'] = [line.strip()]
        return output
    else:
        return None



def reverse_dns(domain_name):
    url = f"https://api.hackertarget.com/reversedns/?q={domain_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        results = response.text.splitlines()
        return results
    else:
        return None
def ipgeotool(domain_name):
    url = f"https://api.hackertarget.com/ipgeo/?q={domain_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        results = response.text.splitlines()
        return results
    else:
        return None
    
def page_extract(domain_name):
    url = f"https://api.hackertarget.com/pagelinks/?q={domain_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        results = response.text.splitlines()
        return results
    else:
        return None
import re

def extract_emails(text):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(pattern, text)
    return emails   

def fetch_all_in_one_data(domain_name):
    url = f"https://netlas-all-in-one-host.p.rapidapi.com/host/{domain_name}/"
    querystring = {"source_type": "include", "fields[0]": "*"}
    headers = {
        "X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
        "X-RapidAPI-Host": "netlas-all-in-one-host.p.rapidapi.com"
    }
    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        return response.json()
    else:
        print("erorrrr")
    