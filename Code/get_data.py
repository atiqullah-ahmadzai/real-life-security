import myutils
import time
import sys
import json
from datetime import datetime

def getChanges(rest):
    """
    Extracts the changes from the raw diff file.
    """
    changes = []
    exts = [".c", ".cpp", ".cc"]
    while "diff --git" in rest:
        start = rest.find("diff --git") + 1
        secondpart = rest.find("index") + 1
        titleline = rest[start:secondpart]  # title line contains the filename info
        # Check if the title line mentions a supported extension.
        if not any(ext in titleline.lower() for ext in exts):
            rest = rest[secondpart + 1:]
            continue
        if "diff --git" in rest[start:]:
            end = rest[start:].find("diff --git")
            filechange = rest[start:end]
            rest = rest[end:]
        else:
            end = len(rest)
            filechange = rest[start:end]
            rest = ""
        filechangerest = filechange
        while "@@" in filechangerest:
            change = ""
            start = filechangerest.find("@@") + 2
            start2 = filechangerest[start:start+50].find("@@") + 2
            start = start + start2
            filechangerest = filechangerest[start:]
            if ("class" in filechangerest or "def" in filechangerest) and "\n" in filechangerest:
                filechangerest = filechangerest[filechangerest.find("\n"):]
            if "@@" in filechangerest:
                end = filechangerest.find("@@")
                change = filechangerest[:end]
                filechangerest = filechangerest[end + 2:]
            else:
                end = len(filechangerest)
                change = filechangerest[:end]
                filechangerest = ""
            if change:
                changes.append([titleline, change])
    return changes

def getFilename(titleline):
    """
    Extracts the filename from the title line of a diff file.
    """
    s = titleline.find(" a/") + 2
    e = titleline.find(" b/")
    name = titleline[s:e]
    exts = [".c", ".cpp", ".cc"]
    if titleline.count(name) == 2:
        return name
    elif any(ext in name.lower() for ext in exts) and (" a" + name + " " in titleline):
        return name
    else:
        print("Couldn't find name", titleline, name)
        return None

def makechangeobj(changething):
    """
    For a single change (titleline and diff content), create an object with details.
    """
    change = changething[1]
    titleline = changething[0]
    if "<html" in change or "sage:" in change or "sage :" in change:
        return None
    thischange = {}
    badpart_result = myutils.getBadpart(change)
    if badpart_result is not None:
        badparts, goodparts = badpart_result
        thischange["diff"] = change
        thischange["add"] = change.count("\n+")
        thischange["remove"] = change.count("\n-")
        thischange["filename"] = getFilename(titleline)
        thischange["badparts"] = badparts
        thischange["goodparts"] = goodparts if goodparts is not None else []
        if thischange["filename"]:
            return thischange
    return None

# ===========================================================================
# Main processing

# Load the commits from the JSON file.
with open("github/c_commits_with_diffs_sample.json", "r") as infile:
    raw_data = json.load(infile)

# Group commits by repository if the raw data is a list.
if isinstance(raw_data, list):
    grouped_data = {}
    for commit in raw_data:
        repo = commit.get("project", "unknown")
        if repo not in grouped_data:
            grouped_data[repo] = []
        grouped_data[repo].append(commit)
else:
    grouped_data = raw_data  # assume already grouped

now = datetime.now()
print("Finished loading at", now.strftime("%H:%M"))

# Set mode from command line (default "overflow")
mode = "dos"
# mode = "overflow"
# mode = "info"
# mode = "bypass"
# mode = "priv"

if len(sys.argv) > 1:
    mode = sys.argv[1]

# Define filtering keywords.
suspiciouswords = ["injection", "vulnerability", "exploit", " ctf",
                   "capture the flag", "ctf", "burp", "capture", "flag", "attack", "hack"]
badwords = ["overflow", "buffer", "stack", "heap", "format", "dos", "arbitrary", "injection"]

# Build the final output: a dictionary mapping repo URLs to a dictionary mapping commit SHA to commit objects.
final_data = {}

for repo, commit_list in grouped_data.items():
    for commit_obj in commit_list:
        # Filter commit: vulnerability field must contain the mode.
        if "vulnerability" not in commit_obj or mode.lower() not in commit_obj["vulnerability"].lower():
            continue
        if "diff" not in commit_obj or not any(ext in commit_obj["diff"].lower() for ext in [".c", ".cpp", ".cc"]):
            continue
        if "message" not in commit_obj:
            commit_obj["message"] = ""
        if any(b.lower() in commit_obj["message"].lower() for b in badwords):
            print("Skipping suspicious commit msg:", commit_obj["message"][:300])
            continue

        changes = getChanges(commit_obj["diff"])
        change_found = False

        # Ensure commit_obj["files"] is a dict.
        if "files" not in commit_obj or not isinstance(commit_obj["files"], dict):
            commit_obj["files"] = {}

        for change in changes:
            thischange = makechangeobj(change)
            if thischange is not None:
                f = thischange["filename"]
                if f is not None:
                    if any(s.lower() in f.lower() for s in suspiciouswords):
                        continue
                    if f not in commit_obj["files"]:
                        commit_obj["files"][f] = {}
                    if "changes" not in commit_obj["files"][f]:
                        commit_obj["files"][f]["changes"] = []
                    commit_obj["files"][f]["changes"].append(thischange)
                    change_found = True

        if change_found:
            # For each file, if "source" and "sourceWithComments" are empty, try to fill them.
            for f in commit_obj["files"]:
                if not commit_obj["files"][f].get("source", "").strip():
                    # Fallback: use the overall diff as a source (may be crude, but provides content)
                    commit_obj["files"][f]["source"] = commit_obj.get("diff", "")
                if not commit_obj["files"][f].get("sourceWithComments", "").strip():
                    commit_obj["files"][f]["sourceWithComments"] = commit_obj.get("diff", "")
            if "msg" not in commit_obj:
                commit_obj["msg"] = commit_obj["message"]
            sha = commit_obj.get("sha", commit_obj.get("commit", None))
            if not sha:
                continue
            commit_obj["sha"] = sha

            # Insert into final_data using repo as key and commit SHA as sub-key.
            if repo not in final_data:
                final_data[repo] = {}
            final_data[repo][sha] = commit_obj
            print("Added commit", sha, "from repo", repo)

print("Done processing. Total commits processed:",
      sum(len(commits) for commits in final_data.values()))

# Save the final output (dict of dicts) to file.
with open("data/plain_" + mode, "w") as outfile:
    json.dump(final_data, outfile)
