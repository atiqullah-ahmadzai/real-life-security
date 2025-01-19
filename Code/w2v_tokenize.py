import sys
import io
import subprocess
import time
import re
from pygments import lex
from pygments.lexers import CLexer
from pygments.token import Token

pythondata = ""

mode = "withString"  # default
# mode = "withoutString"

### Functions ###

# Tokenizer function using Pygments for C language
def tokenize_c_file(block):
    tokens = []
    for token_type, value in lex(block, CLexer()):
        # Filter out whitespace and irrelevant tokens
        if token_type not in [Token.Text.Whitespace, Token.Text, Token.Comment.Multiline]:
            tokens.append((str(token_type), value))
    return tokens

###
if len(sys.argv) > 1:
    mode = sys.argv[1]

# Use the Pygments tokenizer to tokenize the words in the corpus
file_path = "w2v/ctraining_edit.txt"  # Adjust this path to point to your C code file
with open(file_path, 'rb') as file:
    contents = file.read()

# Split the files and merge 10 files together for a single block
array = contents.decode("utf-8").split("\n\n")
merged_elements = ['|'.join(array[i:i + 10]) for i in range(0, len(array), 10)]

single_block = bytes()
for index, block in enumerate(merged_elements):
    print(f"{index} files out of {len(merged_elements)}")
    if block.strip() != "":
        tokens = tokenize_c_file(block)
        tokenized_output = "\n".join([f"{token_type}: '{value}'" for token_type, value in tokens])
        single_block += tokenized_output.encode()

s = io.StringIO(single_block.decode("utf-8", errors='ignore'))

count = 0
totalcount = 0
comment = 0
part = 0

for line in s:
    totalcount += 1
    count += 1
    if totalcount % 1000 == 0:
        print(totalcount)

    position1 = line.find(":") + 1
    position2 = line.find("'")
    position3 = line[position2 + 1:].find("'")

    cat = line[position1:position2]
    content = line[position2 + 1:-2]

    # Skip comments
    if "Comment" in cat:
        comment += 1
        continue

    # Handle strings if mode is "withoutString"
    if mode == "withoutString" and "Literal.String" in cat:
        stringstart = line.find("\"")
        content = line[stringstart + 1:-2]
        content = "\"string\""

    if "Literal.String" in cat or "Keyword" in cat:
        pythondata += " " + content
    elif "Text.Whitespace" in cat:
        pythondata += " "
    elif "Punctuation" in cat:
        pythondata += content
    else:
        pythondata += " " + content

    # Save in parts to reduce computational load
    if count > 1000000:
        print(f"saving part {part} ({mode}) {totalcount}")
        with open(f'w2v/tokenize/ctraining_{mode}_{part}', 'w') as outfile:
            outfile.write(pythondata)
        pythondata = ""
        part += 1
        count = 0

# Final save
with open(f'w2v/tokenize/ctraining_{mode}_{part}', 'w') as outfile:
    outfile.write(pythondata)
