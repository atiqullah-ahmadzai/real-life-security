import os
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Optional: Force CPU usage if needed

import myutils
import sys
import os.path
import json
from datetime import datetime
import random
import pickle
import numpy as np
from keras.models import Sequential
from keras.layers import Dense, LSTM
from keras.preprocessing import sequence
from keras import backend as K
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.utils import class_weight
import tensorflow as tf
from gensim.models import Word2Vec

# Default vulnerability mode
# mode = "dos"
mode = "overflow"
# mode = "info"
# mode = "bypass"
# mode = "priv"

if len(sys.argv) > 1:
    mode = sys.argv[1]

progress = 0
count = 0

### Parameters for sample filtering and creation
restriction = [20000, 5, 6, 10]  # (unused in this snippet)
step = 5                       # step length for sample extraction
fulllength = 200               # desired context length
mode2 = f"{step}_{fulllength}"

### Hyperparameters for the word2vec model
mincount = 10
iterationen = 100
s = 200
w = "withString"
w2v = f"word2vec_{w}{mincount}-{iterationen}-{s}"
w2vmodel = "w2v/" + w2v + ".model"

if not os.path.isfile(w2vmodel):
    print("word2vec model is still being created...")
    sys.exit()

w2v_model = Word2Vec.load(w2vmodel)
# Use key_to_index (gensim 4+)
word_vectors = w2v_model.wv

# Load processed dataset
with open('data/plain_' + mode, 'r') as infile:
    data = json.load(infile)

now = datetime.now()
nowformat = now.strftime("%H:%M")
print("finished loading.", nowformat)

allblocks = []

# Loop over repositories and commits.
# Expected structure: { repo_url: { commit_sha: commit_obj, ... }, ... }
for r in data:
    progress += 1
    for c in data[r]:
        commit_obj = data[r][c]
        if "files" not in commit_obj:
            continue
        print("Processing commit", c, "from repo", r)
        for f in commit_obj["files"]:
            # Try to obtain code from "source"; if empty, use "patch" as fallback.
            if "source" in commit_obj["files"][f] and commit_obj["files"][f]["source"].strip():
                sourcecode = commit_obj["files"][f]["source"]
                print("Found source for file", f)
            elif "patch" in commit_obj["files"][f] and commit_obj["files"][f]["patch"].strip():
                sourcecode = commit_obj["files"][f]["patch"]
                print("Using patch for file", f)
            else:
                print("No source or patch for file", f)
                continue

            # Strip comments (adapted for C code)
            sourcecode = myutils.stripComments(sourcecode)
            allbadparts = []
            if "changes" not in commit_obj["files"][f]:
                continue
            for change in commit_obj["files"][f]["changes"]:
                badparts = change.get("badparts", [])
                count += len(badparts)
                for bad in badparts:
                    pos = myutils.findposition(bad, sourcecode)
                    if -1 not in pos:
                        allbadparts.append(bad)
            if len(allbadparts) > 0:
                positions = myutils.findpositions(allbadparts, sourcecode)
                blocks = myutils.getblocks(sourcecode, positions, step, fulllength)
                print("Extracted", len(blocks), "blocks from file", f)
                for b in blocks:
                    allblocks.append(b)

print("Total blocks extracted:", len(allblocks))
if len(allblocks) == 0:
    print("No blocks were extracted from the dataset. Exiting.")
    sys.exit(1)

# Create randomized keys for splitting samples.
keys = list(range(len(allblocks)))
random.shuffle(keys)

cutoff = round(0.7 * len(keys))   # 70% for training
cutoff2 = round(0.85 * len(keys))  # 15% for validation, 15% for final test

print("cutoff", cutoff)
print("cutoff2", cutoff2)

keystrain = keys[:cutoff]
keystest = keys[cutoff:cutoff2]
keysfinaltest = keys[cutoff2:]

with open('data/' + mode + '_dataset_keystrain', 'wb') as fp:
    pickle.dump(keystrain, fp)
with open('data/' + mode + '_dataset_keystest', 'wb') as fp:
    pickle.dump(keystest, fp)
with open('data/' + mode + '_dataset_keysfinaltest', 'wb') as fp:
    pickle.dump(keysfinaltest, fp)

TrainX = []
TrainY = []
ValidateX = []
ValidateY = []
FinaltestX = []
FinaltestY = []

print("Creating training dataset... (" + mode + ")")
for k in keystrain:
    block = allblocks[k]
    code = block[0]
    token = myutils.getTokens(code)  # Tokenize the snippet
    vectorlist = []
    for t in token:
        if t in word_vectors.key_to_index and t != " ":
            vector = word_vectors[t]
            vectorlist.append(vector.tolist())
    TrainX.append(vectorlist)
    TrainY.append(block[1])

print("Creating validation dataset...")
for k in keystest:
    block = allblocks[k]
    code = block[0]
    token = myutils.getTokens(code)
    vectorlist = []
    for t in token:
        if t in word_vectors.key_to_index and t != " ":
            vector = word_vectors[t]
            vectorlist.append(vector.tolist())
    ValidateX.append(vectorlist)
    ValidateY.append(block[1])

print("Creating finaltest dataset...")
for k in keysfinaltest:
    block = allblocks[k]
    code = block[0]
    token = myutils.getTokens(code)
    vectorlist = []
    for t in token:
        if t in word_vectors.key_to_index and t != " ":
            vector = word_vectors[t]
            vectorlist.append(vector.tolist())
    FinaltestX.append(vectorlist)
    FinaltestY.append(block[1])

print("Train length:", len(TrainX))
print("Test length:", len(ValidateX))
print("Finaltesting length:", len(FinaltestX))
print("time:", datetime.now().strftime("%H:%M"))

print("numpy array done.")
print(f"{len(TrainX)} samples in the training set.")
print(f"{len(ValidateX)} samples in the validation set.")
print(f"{len(FinaltestX)} samples in the final test set.")

csum = sum(TrainY)
if len(TrainX) > 0:
    print("percentage of vulnerable samples: " + str(int((csum / len(TrainX)) * 10000)/100) + "%")
else:
    print("No training samples to compute vulnerability percentage.")

testvul = sum(1 for y in ValidateY if y == 1)
print("absolute amount of vulnerable samples in test set:", testvul)

max_length = fulllength

# LSTM model hyperparameters
dropout = 0.2
neurons = 100
optimizer = "adam"
epochs = 10
batchsize = 128

print("Starting LSTM:")
print("Dropout:", dropout)
print("Neurons:", neurons)
print("Optimizer:", optimizer)
print("Epochs:", epochs)
print("Batch Size:", batchsize)
print("max length:", max_length)

# Pad sequences to uniform length, using float32 type
X_train = sequence.pad_sequences(TrainX, maxlen=max_length, dtype="float32")
X_test = sequence.pad_sequences(ValidateX, maxlen=max_length, dtype="float32")
X_finaltest = sequence.pad_sequences(FinaltestX, maxlen=max_length, dtype="float32")

model = Sequential()
model.add(LSTM(neurons, dropout=dropout, recurrent_dropout=dropout))
model.add(Dense(1, activation='sigmoid'))
model.compile(loss=myutils.f1_loss, optimizer='adam', metrics=[myutils.f1])
print("Compiled LSTM.")

# Compute class weights and convert to dictionary
TrainY_np = np.array(TrainY)
classes = np.unique(TrainY_np)
weights = class_weight.compute_class_weight(class_weight='balanced', classes=classes, y=TrainY_np)
class_weights = {int(cls): weight for cls, weight in zip(classes, weights)}

history = model.fit(X_train, TrainY_np, epochs=epochs, batch_size=batchsize, class_weight=class_weights)

# Prediction: use model.predict() and threshold at 0.5
def get_pred_classes(X):
    yhat_probs = model.predict(X, verbose=0)
    return (yhat_probs > 0.5).astype("int32")

for dataset in ["train", "test", "finaltest"]:
    print("Now predicting on " + dataset + " set (" + str(dropout) + " dropout)")
    if dataset == "train":
        yhat_classes = get_pred_classes(X_train)
        accuracy = accuracy_score(TrainY_np, yhat_classes)
        precision = precision_score(TrainY_np, yhat_classes)
        recall = recall_score(TrainY_np, yhat_classes)
        F1Score = f1_score(TrainY_np, yhat_classes)
    elif dataset == "test":
        yhat_classes = get_pred_classes(X_test)
        accuracy = accuracy_score(np.array(ValidateY), yhat_classes)
        precision = precision_score(np.array(ValidateY), yhat_classes)
        recall = recall_score(np.array(ValidateY), yhat_classes)
        F1Score = f1_score(np.array(ValidateY), yhat_classes)
    elif dataset == "finaltest":
        yhat_classes = get_pred_classes(X_finaltest)
        accuracy = accuracy_score(np.array(FinaltestY), yhat_classes)
        precision = precision_score(np.array(FinaltestY), yhat_classes)
        recall = recall_score(np.array(FinaltestY), yhat_classes)
        F1Score = f1_score(np.array(FinaltestY), yhat_classes)
    print("Accuracy:", accuracy)
    print("Precision:", precision)
    print("Recall:", recall)
    print("F1 score:", F1Score)
    print("\n")

print("Saving LSTM model " + mode + ".")
model.save('model/LSTM_model_' + mode + '.h5')
print("Done.")
