import unittest
import requests
import subprocess
import time
import sys
import jwt

def fail(msg):
    print('error:', msg)

def extract_uuid(cookies):
    decoded = jwt.decode(cookies['access_token'], verify=False, algorithms='HS256')
    if 'UserID' not in decoded:
        fail('unable to find UUID in access token - tests may fail')
        return ''
    return decoded['UserID']

def main():
    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user', 'email': 'test_email@berkeley.edu', 'password': 'test_password'}
    response = requests.post(url, json=payload)
    global user_cookies
    user_cookies = response.cookies
    global user_uuid
    user_uuid = extract_uuid(user_cookies)

    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user2', 'email': 'test_email2@berkeley.edu', 'password': 'test_password2'}
    response = requests.post(url, json=payload)
    global user2_cookies
    user2_cookies = response.cookies
    global user2_uuid
    user2_uuid = extract_uuid(user2_cookies)

    print('Running profile set tests...')
    test_set()
    print('Finished profile set tests')

    print('Running profile get tests...')
    test_get()
    print('Finished posts create tests')

def test_set():
    url = "http://localhost:82/api/profile/{}".format(user_uuid)
    payload = {'firstName': 'Test', 'lastName': 'User', 'uuid': user_uuid, 'email': 'contact_email@berkeley.edu'}
    response = requests.put(url, json=payload, cookies=user_cookies)
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))

    url = "http://localhost:82/api/profile/{}".format(user2_uuid)
    payload = {'firstName': 'Test', 'lastName': 'User2', 'uuid': user2_uuid, 'email': 'contact_email2@berkeley.edu'}
    response = requests.put(url, json=payload, cookies=user2_cookies)
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))

def test_get():
    url = "http://localhost:82/api/profile/{}".format(user_uuid)
    response = requests.get(url, cookies=user_cookies)
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))
    else:
        json = response.json()

        if 'firstName' not in json:
            fail('firstName not in response')
        elif json['firstName'] != 'Test':
            fail('expected firstName {} but was {}'.format('Test', json['firstName']))

        if 'lastName' not in json:
            fail('lastName not in response')
        elif json['lastName'] != 'User':
            fail('expected lastName {} but was {}'.format('User', json['lastName']))

        if 'uuid' not in json:
            fail('uuid not in response')
        elif json['uuid'] != user_uuid:
            fail('expected uuid {} but was {}'.format(user_uuid, json['uuid']))

        if 'email' not in json:
            fail('email not in response')
        elif json['email'] != 'contact_email@berkeley.edu':
            fail('expected email {} but was {}'.format('contact_email@berkeley.edu', json['email']))

    url = "http://localhost:82/api/profile/{}".format(user2_uuid)
    response = requests.get(url, cookies=user2_cookies)
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))
    else:
        json = response.json()

        if 'firstName' not in json:
            fail('firstName not in response')
        elif json['firstName'] != 'Test':
            fail('expected firstName {} but was {}'.format('Test', json['firstName']))

        if 'lastName' not in json:
            fail('lastName not in response')
        elif json['lastName'] != 'User2':
            fail('expected lastName {} but was {}'.format('User2', json['lastName']))

        if 'uuid' not in json:
            fail('uuid not in response')
        elif json['uuid'] != user2_uuid:
            fail('expected uuid {} but was {}'.format(user2_uuid, json['uuid']))

        if 'email' not in json:
            fail('email not in response')
        elif json['email'] != 'contact_email2@berkeley.edu':
            fail('expected email {} but was {}'.format('contact_email2@berkeley.edu', json['email']))

if __name__ == '__main__':
    main()
