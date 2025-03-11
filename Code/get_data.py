import myutils
import sys
import json
from datetime import datetime

def get_changes(rest):
    """
    Extracts diff changes from the raw diff string.
    Returns a list of [titleline, change] pairs.
    """
    changes = []
    exts = [".c", ".cpp", ".cc"]
    while "diff --git" in rest:
        start = rest.find("diff --git") + 1
        secondpart = rest.find("index") + 1
        titleline = rest[start:secondpart]  # Title line contains filename info
        if not any(ext in titleline.lower() for ext in exts):
            rest = rest[secondpart + 1:]
            continue
        if "diff --git" in rest[start:]:
            end = rest[start:].find("diff --git")
            filechange = rest[start:start+end]
            rest = rest[start+end:]
        else:
            filechange = rest[start:]
            rest = ""
        filechangerest = filechange
        while "@@" in filechangerest:
            change = ""
            start_marker = filechangerest.find("@@") + 2
            # Attempt to locate the next @@ marker within a window
            start2 = filechangerest[start_marker:start_marker+50].find("@@")
            start2 = start2 + 2 if start2 != -1 else len(filechangerest[start_marker:])
            start_marker = start_marker + start2
            filechangerest = filechangerest[start_marker:]
            if ("class" in filechangerest or "def" in filechangerest) and "\n" in filechangerest:
                filechangerest = filechangerest[filechangerest.find("\n"):]
            if "@@" in filechangerest:
                end = filechangerest.find("@@")
                change = filechangerest[:end]
                filechangerest = filechangerest[end + 2:]
            else:
                change = filechangerest
                filechangerest = ""
            if change:
                changes.append([titleline, change])
    return changes

def get_filename(titleline):
    """
    Extracts the filename from the diff title line.
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
        print("Couldn't find name in titleline:", titleline, name)
        return None

def make_change_obj(changething):
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
        thischange["filename"] = get_filename(titleline)
        thischange["badparts"] = badparts
        thischange["goodparts"] = goodparts if goodparts is not None else []
        if thischange["filename"]:
            return thischange
    return None

def process_commits(raw_data, mode):
    # Group commits by repository
    if isinstance(raw_data, list):
        grouped_data = {}
        for commit in raw_data:
            repo = commit.get("project", "unknown")
            grouped_data.setdefault(repo, []).append(commit)
    else:
        grouped_data = raw_data

    now = datetime.now()
    print("Finished loading at", now.strftime("%H:%M"))

    # Filtering keywords
    suspiciouswords = ["injection", "vulnerability", "exploit", " ctf",
                       "capture the flag", "ctf", "burp", "capture", "flag", "attack", "hack"]
    badwords = ["overflow", "buffer", "stack", "heap", "format", "dos", "arbitrary", "injection"]

    final_data = {}
    for repo, commit_list in grouped_data.items():
        for commit_obj in commit_list:
            if "vulnerability" not in commit_obj or mode.lower() not in commit_obj["vulnerability"].lower():
                continue
            if "diff" not in commit_obj or not any(ext in commit_obj["diff"].lower() for ext in [".c", ".cpp", ".cc"]):
                continue
            if "message" not in commit_obj:
                commit_obj["message"] = ""
            if any(b.lower() in commit_obj["message"].lower() for b in badwords):
                print("Skipping suspicious commit msg:", commit_obj["message"][:300])
                continue

            changes = get_changes(commit_obj["diff"])
            change_found = False

            # Ensure files field is a dictionary
            if "files" not in commit_obj or not isinstance(commit_obj["files"], dict):
                commit_obj["files"] = {}

            for change in changes:
                thischange = make_change_obj(change)
                if thischange is not None:
                    f = thischange["filename"]
                    if f is not None:
                        if any(s.lower() in f.lower() for s in suspiciouswords):
                            continue
                        commit_obj["files"].setdefault(f, {}) \
                                          .setdefault("changes", []).append(thischange)
                        change_found = True

            if change_found:
                # Ensure source code is available in file data
                for f in commit_obj["files"]:
                    if not commit_obj["files"][f].get("source", "").strip():
                        commit_obj["files"][f]["source"] = commit_obj.get("diff", "")
                    if not commit_obj["files"][f].get("sourceWithComments", "").strip():
                        commit_obj["files"][f]["sourceWithComments"] = commit_obj.get("diff", "")
                if "msg" not in commit_obj:
                    commit_obj["msg"] = commit_obj["message"]
                sha = commit_obj.get("sha", commit_obj.get("commit", None))
                if not sha:
                    continue
                commit_obj["sha"] = sha
                final_data.setdefault(repo, {})[sha] = commit_obj
                print("Added commit", sha, "from repo", repo)
    return final_data

def main():
    mode = "dos"
    #mode = "overflow"
    #mode = "info"
    #mode = "bypass"
    #mode = "priv" 

    if len(sys.argv) > 1:
        mode = sys.argv[1]
    try:
        with open("github/c_commits_with_diffs_sample.json", "r") as infile:
            raw_data = json.load(infile)
    except Exception as e:
        print("Error loading JSON file:", e)
        sys.exit(1)
    final_data = process_commits(raw_data, mode)
    total = sum(len(commits) for commits in final_data.values())
    print("Done processing. Total commits processed:", total)
    output_file = "data/plain_" + mode
    with open(output_file, "w") as outfile:
        json.dump(final_data, outfile)
    print("Saved processed data to", output_file)

if __name__ == "__main__":
    main()
