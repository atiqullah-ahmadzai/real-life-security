import sys
from io import StringIO
import subprocess
import time

# Remove some problematic code or patterns in the C source code corpus

# Open and read the C source code file
f = open("w2v/ctraining.txt", "r")
contents = f.read()
contents = contents.replace('\t', '    ')  # Replace tabs with spaces for consistency

# Example replacements for known C code patterns (update these based on specific requirements)
if 'int main(\n                int argc' in contents:
    pos = contents.find('int main(\n                int argc')
    contents = contents[:pos-198] + contents[pos+178:]

if "            perror(\"Some Error Message\");" in contents:
    pos = contents.find("            perror(\"Some Error Message\");")
    length = len("            perror(\"Some Error Message\");")
    contents = contents[:pos] + contents[pos+length+1:]

if "int result[k]*factor+base;" in contents:
    pos = contents.find("int result[k]*factor+base;")
    contents = contents[:pos+17] + contents[pos+21:]

# List of specific problematic strings to remove or replace
badstring = ["bad_field", "malloc(sizeof(int)*10)"]

# Removing unwanted sections
fromhere = 0
while "check_structure.DataSet." in contents:
    pos = contents.find("check_structure.DataSet.")
    area = contents[pos-300:pos+300]
    start = area.find("struct")
    end = area.find("int")  # Update this based on C structure patterns
    contents = contents[:pos-300+start] + contents[pos-300+end:]

# Handling specific patterns that should be removed
fromhere = 0
while "KEY_SECRET" in contents[fromhere:] and "ENCRYPTION_TYPE" in contents[fromhere:fromhere+2000]:
    pos = fromhere + contents[fromhere:].find("KEY_SECRET")
    area = contents[pos-1000:pos+1000]
    start = area[:1000].find("struct")
    if start == -1:
        start = area[:1000].find("#include")
    if start == -1:
        start = area[:1000].find("int")
        
    end = area[1000:].find("void")
    if end == -1:
        end = area[1000:].find("#define")
    
    print("Found pattern at " + str(pos))
    if start > 0 and end > 0:
        contents = contents[:pos-1000+start] + contents[pos-1000+end:]
        fromhere = pos - 1000 + start + end + 1
        print("Continuing at " + str(fromhere))
    else:
        fromhere = pos + 1000

# Removing hard-coded passwords or credentials
fromhere = 0
while "password123" in contents[fromhere:]:
    pos = fromhere + contents[fromhere:].find("password123")
    area = contents[pos-1000:pos+1000]
    start = area.find("void")
    end = area[1000:].find("void")
    if end == -1:
        end = area[1000:].find("#include")
    if start > 0 and end > 0:
        contents = contents[:pos-1000+start] + contents[pos+end:]
        fromhere = pos - 1000 + start
    else:
        fromhere = pos + 1

# Additional specific patterns to find and remove
if "password123" in contents and "adminuser" in contents and "localhost" in contents:
    pos = contents.find("password123")

for x in badstring:
    while x in contents:    
        pos = contents.find(x)    
        area = contents[pos-500:pos+1000]            
        if("malloc" in area):
            contents = contents.replace("malloc(sizeof(int)*10)", "calloc(10, sizeof(int))", 1)
            continue
        start = area.find("struct")    
        restarea = area[start:]    
        end = restarea.find("#include") + start
        end2 = restarea.find("#define") + start    
        if end2 < end:
            end = end2 
        if end > start:
            contents = contents[:pos-500+start] + contents[pos-500+end:]

# Write the modified contents back to a new C file
f = open("w2v/ctraining_edit.txt", "w")
f.write(contents)
f.close()
