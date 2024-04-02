import requests

# url = "https://netdetective.p.rapidapi.com/query"

# querystring = {"ipaddress":"172.66.41.24"}

# headers = {
# 	"X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
# 	"X-RapidAPI-Host": "netdetective.p.rapidapi.com"
# }

# response = requests.get(url, headers=headers, params=querystring)

# print(response.json())


# <!-- ----------------------------------------------------------------------------------------- -->


import requests

url = "https://ip-iq.p.rapidapi.com/ip"

querystring = {"ip":"185.246.188.140"}

headers = {
	"X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
	"X-RapidAPI-Host": "ip-iq.p.rapidapi.com"
}

response = requests.get(url, headers=headers, params=querystring)

print(response.json()) 

