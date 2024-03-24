import requests

def check_cloudflare(url):
    try:
        response = requests.get(url)
        headers = response.headers
        
        # Check Server header
        server_header = headers.get('Server')
        if server_header and 'cloudflare' in server_header.lower():
            return True
        
        # Check CF-RAY header
        cf_ray_header = headers.get('CF-RAY')
        if cf_ray_header:
            return True
        
        # Check X-Cache header
        x_cache_header = headers.get('X-Cache')
        if x_cache_header and 'cloudflare' in x_cache_header.lower():
            return True
        
        # Check nameservers
        nameservers = requests.get(f'http://api.hackertarget.com/dnslookup/?q={url}').text
        if 'cloudflare' in nameservers:
            return True
        
        return False
    
    except Exception as e:
        print("Error:", e)
        return False

def main():
    url = input("Enter the URL to check: ")
    if url.startswith("http://") or url.startswith("https://"):
        pass
    else:
        url = "http://" + url
    
    is_cloudflare = check_cloudflare(url)
    
    if is_cloudflare:
        print(f"The website '{url}' is behind Cloudflare.")
    else:
        print(f"The website '{url}' is not behind Cloudflare.")

if __name__ == "__main__":
    main()
