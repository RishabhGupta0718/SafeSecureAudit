from django.shortcuts import render
from .utils import portscanner
from .utils.dnsresolver import dns_record_lookup
from .utils.waf import check_cloudflare
import requests

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
        return "erorrrr"

def index(request):
    tool = request.GET.get('tool', '')
    if request.method == 'POST':
        domain_name = request.POST.get('websiteUrl')
        if tool == "allinone":
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            domain_data = fetch_all_in_one_data(domain_name)
            return render(request, 'index.html', {'domain_data': domain_data,"tool":tool})
        elif tool == 'dnsresolvertool':
            record_types = ["A", "MX", "TXT", "NS"]
            dns_results = {}
            for record_type in record_types:
                dns_results[record_type] = dns_record_lookup(domain_name, record_type)
            context = {'tool': tool, 'dns_results': dns_results}
            return render(request, 'index.html', context)
        
        elif tool == 'portscanner':
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            open_ports = portscanner.port_scan(domain_name)
            context = {'open_ports': open_ports, 'tool': tool, 'domain_name': domain_name}
            return render(request, 'index.html', context)
        
        elif tool == 'waf':
            if not domain_name.startswith(('http://', 'https://')):
                domain_name = "https://" + domain_name
            is_cloudflare = check_cloudflare(domain_name)
            context = {'tool': tool, 'is_cloudflare': is_cloudflare, 'domain_name': domain_name}
            return render(request, 'index.html', context)
        
        else:
            return render(request, 'index.html', {'error_message': 'Invalid tool specified.'})
    
    else:
        return render(request, 'index.html')
