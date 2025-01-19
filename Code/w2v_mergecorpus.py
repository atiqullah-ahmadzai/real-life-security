fulltext = ""
text = []
mode = "withString"
for i in range(0,44):
  f=open("w2v/tokenize/ctraining_" + mode + "_" + str(i), "r")
  contents =f.read()
  fulltext = fulltext + contents
  print("loaded " + str(i))
with open('w2v/tokenize/ctraining_'+mode+"_X", 'w') as outfile:
  outfile.write(fulltext)
