import requests
import time
import sys
import json
import datetime
import os
from dotenv import load_dotenv

# get github token from .env
load_dotenv("../.env")
access_token = os.getenv('GITHUB_TOKEN')

# load C_CommitsWithDiffs.json if exists


# load all_commits.json
all_commits = []
with open('github/all_commits.json', 'r') as infile:
    all_commits = json.load(infile)

diff_commits = []
if os.path.exists('github/c_commits_with_diffs.json'):
    with open('github/c_commits_with_diffs.json', 'r') as infile:
        diff_commits = json.load(infile)
else:
    diff_commits = all_commits

# loop into the all commits and get the diff
i = 0
for commit in diff_commits:
    # Save your progress
    # if i > 4000:
    #     break
    
    target   = commit['url']+".diff"
    if "diff" in commit:
        print("Skip "+str(i)+" commits from "+str(len(all_commits)))
        i += 1
        continue
    
    try:
        response = requests.get(target, headers={'Authorization': 'token ' + access_token})
    except:
        continue
    response = requests.get(target, headers={'Authorization': 'token ' + access_token})
    content  = response.content
    try:
        diffcontent = content.decode('utf-8', errors='ignore')
    except:
        print("an exception occurred. Skip.")
    else:
        commit["diff"] = diffcontent

    print("Done "+str((i))+" commits from "+str(len(all_commits)))
    i += 1
    
with open('github/c_commits_with_diffs.json', 'w') as outfile:
    json.dump(diff_commits, outfile, indent=4)
    

    
