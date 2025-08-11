import requests

import json

link=input("Enter the url: ")

api_key=''
url='https://www.virustotal.com/vtapi/v2/url/report'

params={'apikey':api_key,'resource':url}
response=requests.get(url,params=params)
response_json = response.json()
if response_json['positives'] <= 0:
    print("NOT MALICIOUS")
elif 1>=response_json['positive']>=3:
    print("MIGHT BE MALICIOUS")
elif response_json['positive']>=4:
    print("MALICIOUS")  
else:
    print("URL Not Found")        