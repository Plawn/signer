import base64
import requests
import json


url = "http://localhost:3000"

d =  bytearray([1, 2, 3])

def test_stamper():
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

# test_stamper()

# def test_authority():
#     url = "http://localhost:8080"
#     with open('archive/0193ef9a-e733-73f2-bd15-247bfdd5fc24.json', 'r') as f :
#         data = json.load(f)
#     print(data)
#     req = requests.post(f'{url}/sign', json=data['response'])
#     print(req.status_code)
#     print(req.text)

# test_authority()


def test_front():
    url = "http://localhost:4000"
    with open('signed.json', 'r') as f :
        data = json.load(f)
    print(data)
    req = requests.post(f'{url}/sign', json=data)
    print(req.status_code)
    print(req.text)

test_front()