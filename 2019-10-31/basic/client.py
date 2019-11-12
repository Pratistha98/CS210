#!/usr/bin/env python3

import json
import pprint
import requests

pprinter = pprint.PrettyPrinter(indent=1)

print("Getting All Posts")
print('='*80)
r = requests.get("http://localhost:5000/api/v1/posts/")
pprinter.pprint(r.json())

print("Individually Getting Posts 1-3")
print('='*80)
for pid in range(1,4):
	r = requests.get("http://localhost:5000/api/v1/posts/"+str(pid))
	pprinter.pprint(r.json())

print("\n\n\nAdding another post")
print('='*80)
post = {'text': ("Please don't cook me, kind sirs! I am a good cook myself, "
	"and cook better than I cook, if you see what I mean.")}
r = requests.post("http://localhost:5000/api/v1/posts/", json=post)
pprinter.pprint(r.json())

print("\n\n\nDeleting an old post 6")
print('='*80)
r = requests.delete("http://localhost:5000/api/v1/posts/6")
pprinter.pprint(r.json())

print("\n\n\nGetting All Posts (Again)")
print('='*80)
r = requests.get("http://localhost:5000/api/v1/posts/")
pprinter.pprint(r.json())