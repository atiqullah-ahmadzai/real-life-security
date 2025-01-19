import json

"""
Format all c_commits_with_diffs.json and save it in github/clean_commits.json
from
       c["url"]      = row["ref_link"]
        c["message"]  = row["summary"]
        c["commit"]   = row["commit_id"]
        c['project']  = row['project']
        c['date']     = row['update_date']
        c['files']    = file_changed
        c["before_fix"] = row["version_before_fix"]
        c["after_fix"] = row["version_after_fix"]
        c['vulnerability'] = row['vulnerability_classification'].strip()
        c['diff'] = row['diff']

to this
{
    "repo1": {
        "commit1": {
            "author": "author_name",
            "date": "2023-10-01T12:34:56Z",
            "message": "Initial commit",
            "diff": "diff --git a/file1.py b/file1.py\nindex 83db48f..b1c0d1e 100644\n--- a/file1.py\n+++ b/file1.py\n@@ -1,4 +1,4 @@\n-print('Hello, world!')\n+print('Hello, Python!')\n"
        },
        "commit2": {
            "author": "author_name",
            "date": "2023-10-02T12:34:56Z",
            "message": "Added new feature",
            "diff": "diff --git a/file2.py b/file2.py\nindex 83db48f..b1c0d1e 100644\n--- a/file2.py\n+++ b/file2.py\n@@ -1,4 +1,4 @@\n-def feature():\n+def new_feature():\n    pass\n"
        }
    },
    "repo2": {
        "commit1": {
            "author": "another_author",
            "date": "2023-10-03T12:34:56Z",
            "message": "Fixed bug",
            "diff": "diff --git a/file3.py b/file3.py\nindex 83db48f..b1c0d1e 100644\n--- a/file3.py\n+++ b/file3.py\n@@ -1,4 +1,4 @@\n-def bug():\n+def fix_bug():\n    pass\n"
        }
    }
}       
"""

all_commits = []
with open('github/c_commits_with_diffs.json', 'r') as infile:
    all_commits = json.load(infile)

clean_commits = {}


for c in all_commits:
    project_url = c['url'].split("/commit")[0]
    commit_id = c['commit']
    if "overflow" not in c["vulnerability"].strip().lower():
        continue
    if project_url not in clean_commits:
        clean_commits[project_url] = {}
    if "diff" in c:
        clean_commits[project_url][commit_id] = {
            "author": "",
            "date": c["date"],
            "message": c["message"],
            "diff": c["diff"],
            "keyword": c["vulnerability"],
            "files":  {}
        }
        break

with open('github/clean_commits.json', 'w') as outfile:
    json.dump(clean_commits, outfile, indent=4)


