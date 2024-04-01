from django.shortcuts import render
from .utils import portscanner
from .utils.tool import dns_record_lookup,dnslookup,reverse_dns,ipgeotool,page_extract,extract_emails,fetch_all_in_one_data
from .utils.waf import check_cloudflare
from .utils.phone_info_tool import gather_phone_info

def index(request):
    tool = request.GET.get('tool', '')
    if request.method == 'POST':
        domain_name = request.POST.get('websiteUrl')
        if tool == "allinone":
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            domain_data = fetch_all_in_one_data(domain_name)
            return render(request, 'tools/allinone.html', {'domain_data': domain_data,"tool":tool})
        
        elif tool == 'dnsresolvertool':
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            record_types = ["A", "MX", "TXT", "NS"]
            dns_results = {}
            for record_type in record_types:
                dns_results[record_type] = dns_record_lookup(domain_name, record_type)
            context = {'tool': tool, 'dns_results': dns_results}
            return render(request, 'index.html', context)
        
        elif tool == "dnslookuptool":
            dns_results = dnslookup(domain_name)
            return render(request, 'tools/dnslookuptool.html', {'tool':tool,'domain_name': domain_name, 'dns_results': dns_results})
        
        elif tool == "reversednstool":
            reverse_dns_results = reverse_dns(domain_name)
            return render(request, 'tools/reversednstool.html', {'tool': tool, 'domain_name': domain_name, 'reverse_dns_results': reverse_dns_results})
        
        elif tool  == "ipgeotool":
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            ipgeotool_results = ipgeotool(domain_name)
            return render(request, 'tools/ipgeotool.html', {'tool': tool, 'domain_name': domain_name, 'ipgeotool_results': ipgeotool_results})
        
        elif tool == "page_extract":
            page_extract_results = page_extract(domain_name)
            return render(request, 'tools/page_extract.html', {'tool': tool, 'domain_name': domain_name,'page_extract_results':page_extract_results})

        elif tool == 'portscanner':
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            open_ports = portscanner.port_scan(domain_name)
            context = {'open_ports': open_ports, 'tool': tool, 'domain_name': domain_name}
            return render(request, 'tools/portscanner.html', context)
        
        elif tool == 'waf':
            if not domain_name.startswith(('http://', 'https://')):
                domain_name = "https://" + domain_name
            is_cloudflare = check_cloudflare(domain_name)
            context = {'tool': tool, 'is_cloudflare': is_cloudflare, 'domain_name': domain_name}
            return render(request, 'tools/waf.html', context)
        
        elif tool == "phoneinfo":
            phone_info_results = gather_phone_info(domain_name)
            return render(request, 'tools/phoneinfo.html', {'tool': tool, 'domain_name': domain_name, 'phone_info_results': phone_info_results})
        
        elif tool == "extract_emails":
            extract_emails_results = extract_emails(domain_name)
            return render(request, 'tools/extract_emails.html', {'tool': tool, 'domain_name': domain_name,'extract_emails_results':extract_emails_results})
        
        else:
            return render(request, 'index.html', {'error_message': 'Please select provided tool on sidebar.'})
    if request.method == 'GET':
        if tool == "allinone":
             return render(request, 'tools/allinone.html')
        
        elif tool == 'dnsresolvertool':
            return render(request, 'tools/dnsresolvertool.html')

        elif tool == "dnslookuptool":
            return render(request, 'tools/dnslookuptool.html')
        
        elif tool == "reversednstool":
            return render(request, 'tools/reversednstool.html')
        
        elif tool  == "ipgeotool":
            return render(request, 'tools/ipgeotool.html')
        
        elif tool == "page_extract":
            return render(request, 'tools/page_extract.html')

        elif tool == 'portscanner':
            return render(request, 'tools/portscanner.html')
        
        elif tool == 'waf':
            return render(request, 'tools/waf.html')
        
        elif tool == "phoneinfo":
            return render(request, 'tools/phoneinfo.html')
        
        elif tool == "extract_emails":
            return render(request, 'tools/extract_emails.html')
        else:
            return render(request, 'index.html', {'error_message': 'Please select provided tool on sidebar.'})


def learning(request):
    learn = request.GET.get('learn', '')
    if request.method == 'GET':
        if learn == "Arbitrary_File_Upload":
            return render(request,template_name="learning/Arbitrary_File_Upload.html")
        elif learn == "CRLF_Injection":
            return render(request,template_name="learning/CRLF_Injection.html")
        elif learn == "csrf":
            return render(request,template_name="learning/csrf.html")
        elif learn == "xss":
            return render(request,template_name="learning/xss.html")
        elif learn == "dos":
            return render(request,template_name="learning/dos.html")
        elif learn == "ExposedSourceCode":
            return render(request,template_name="learning/ExposedSourceCode.html")
        elif learn == "HostHeaderInjection":
            return render(request,template_name="learning/Host Header Injection.html")
        elif learn == "InsecureDirectObjectReferences":
            return render(request,template_name="learning/Insecure Direct Object References.html")
        else:
            return render(request,template_name="learning/learning.html")
        