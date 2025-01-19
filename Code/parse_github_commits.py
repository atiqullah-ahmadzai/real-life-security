import os
import requests
import time
import sys
import json
from requests_oauthlib import OAuth1Session
from requests_oauthlib import OAuth1
import pandas as pd

# load dataset into pandas
dataset = pd.read_csv('../dataset/c_release2.0.csv')

# save dataset to json
dataset.to_json('github/c_release2.0.json', orient='records', lines=True)

# clean nan values
dataset = dataset.fillna('')

# for each row in the dataset get the commits
commits = []
i = 0
print("Total Rows",len(dataset))
for index, row in dataset.iterrows():
    c = {}
    
    # decode json string to dict and if error skip the itiration
    file_changed = ""
    try:
        # replace all <_**next**_> in files_changed with , to make it a valid json string
        file_changed = "["+row['files_changed'].replace('<_**next**_>', ',')+"]"
        file_changed = file_changed.replace('"<_**next**_>"', ',')
        if file_changed[-1] == ',':
            file_changed = file_changed[:-1]
            
        file_changed = json.loads(file_changed)
        c["url"]      = row["ref_link"]
        c["message"]  = row["summary"]
        c["commit"]   = row["commit_id"]
        c['project']  = row['project']
        c['date']     = row['update_date']
        c['files']    = file_changed
        c["before_fix"] = row["version_before_fix"]
        c["after_fix"] = row["version_after_fix"]
        c['vulnerability'] = row['vulnerability_classification'].strip()
        commits.append(c)
    except:
        i+=1
        continue
        
    
# save it in all_commits.json
with open('github/all_commits.json', 'w') as f:
    json.dump(commits, f)

print('Error decoding json string '+ str(i))
    

