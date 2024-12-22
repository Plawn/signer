import base64
import requests
import json

url = "http://localhost:8080"

d =  bytearray([1, 2, 3])

def test():
    # data = {
    #     "data":base64.b64encode(d).decode('utf-8'),
    #     "signature":base64.b64encode(d).decode('utf-8'),
    # }
    with open('signed.json', 'r') as f :
        data = json.load(f)
    print(data)
    req = requests.post(f'{url}/sign', json=data)
    print(req.status_code)
    print(req.text)
    # print(req.json())

test()