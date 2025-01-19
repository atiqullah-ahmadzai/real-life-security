from pydriller import Repository
import sys

# collect all python code for building a corpus to train the word2vec model

# https://github.com/trending/c
# Top C Repositories
repos = [
    "https://github.com/yugabyte/yugabyte-db",
    "https://github.com/karpathy/llama2.c",
    "https://github.com/nginx/nginx",
    "https://github.com/open62541/open62541",
    "https://github.com/lvgl/lvgl",
    "https://github.com/koekeishiya/yabai",
    "https://github.com/nothings/stb",
    "https://github.com/madler/zlib",
]

ctraining = ""

for r in repos:
    print(r)
    files = []
    for commit in Repository(r).traverse_commits():
        for m in commit.modified_files:
            filename = m.new_path

            if filename is not None:
                # Get only .c not .cc or .hh
                if filename.endswith(".c") or filename.endswith(".h"):
                    if not filename in files:
                        code = m.source_code
                        if code is not None:
                            ctraining = ctraining + "\n\n" + code
                            print(filename)
                            files.append(filename)

    with open("w2v/ctraining.txt", "w") as outfile:
        outfile.write(ctraining)
