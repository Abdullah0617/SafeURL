import requests

import json

link=input("Enter the url: ")

api_key='e90aae7b6f77f64baf70ea674a4b02a33c8cacd00fccda178324284fd4f22ee3'
url='https://www.virustotal.com/vtapi/v2/url/report'

params={'apikey':api_key,'resource':url}
response=requests.get(url,params=params)
response_json = response.json()
if response_json['positives'] <= 0:
    print("Good")
elif 1>=response_json['positive']>=3:
    print("Fine")
elif response_json['positive']>=4:
    print("Bad")  
else:
    print("URL Not Found")        