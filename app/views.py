from django.shortcuts import render
from .utils import portscanner
from .utils.dnsresolver import dns_record_lookup
from .utils.waf import check_cloudflare
import socket

def index(request):
    tool = request.GET.get('tool', '')
    if request.method == 'POST':
        domain_name = request.POST.get('websiteUrl')
        if tool == 'dnsresolvertool':
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
