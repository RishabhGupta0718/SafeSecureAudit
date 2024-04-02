# DATA BREACH API ONLY 100 REQUESTS
import requests
url = "https://credential-verification.p.rapidapi.com/restpeopleMOB/MA/MaWcf.svc/Makshouf"
payload = {
	"Service_Flag": "",
	"Criterias": [
		{
			"Field": "page",
			"Value": "1"
		},
		{
			"Field": "SEARCH_KEY",
			"Value": "sachinkewat809@gmail.com"
		}
	]
}
headers = {
	"content-type": "application/json",
	"X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
	"X-RapidAPI-Host": "credential-verification.p.rapidapi.com"
}
response = requests.post(url, json=payload, headers=headers)
print(response.json())