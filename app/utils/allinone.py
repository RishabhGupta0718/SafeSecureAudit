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
        print(response.json())
    else:
        return None

fetch_all_in_one_data("saketcollege.edu.in")