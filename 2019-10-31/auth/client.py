#!/usr/bin/env python3

import json
import pprint
import base64
import requests
from requests.auth import HTTPBasicAuth

pprinter = pprint.PrettyPrinter(indent=1)

username, password = "bdicken3", 'really"good"password'

print("Getting All Users")
print('='*80)
r = requests.get("http://localhost:5000/api/v1/users/")
r.raise_for_status()
pprinter.pprint(r.json())

print("\n\n\nCreating a User")
print('='*80)
user = {'username': username, 'password': password}
r = requests.post("http://localhost:5000/api/v1/users/", json=user)
r.raise_for_status()
pprinter.pprint(r.json())

print("\n\n\nGetting All Users")
print('='*80)
r = requests.get("http://localhost:5000/api/v1/users/")
r.raise_for_status()
pprinter.pprint(r.json())

print("\n\n\nDeleting User")
print('='*80)
try:
	r = requests.delete("http://localhost:5000/api/v1/users/1")
	r.raise_for_status()
	pprinter.pprint(r.json())
except Exception as e:
	print(e)

print("\n\n\nLogging In")
print('='*80)
try:
	r = requests.get("http://localhost:5000/api/v1/token", 
		auth=HTTPBasicAuth(username, password))
	r.raise_for_status()
	token = r.json().get("token")
	pprinter.pprint(r.json())
except Exception as e:
	print(e)

print("\n\n\nChanging Username and Password")
print('='*80)
try:
	r = requests.put("http://localhost:5000/api/v1/users/1", 
		json={
			'token': token, 
			'user': {
				'username': 'bdickin3', 
				'password': password
			}
		})
	r.raise_for_status()
	pprinter.pprint(r.json())
except Exception as e:
	print(e)

print("\n\n\nDeleting User")
print('='*80)
try:
	r = requests.delete("http://localhost:5000/api/v1/users/1", 
		json={'token': token})
	r.raise_for_status()
	pprinter.pprint(r.json())
except Exception as e:
	print(e)

print("\n\n\nGetting All Users")
print('='*80)
r = requests.get("http://localhost:5000/api/v1/users/")
pprinter.pprint(r.json())