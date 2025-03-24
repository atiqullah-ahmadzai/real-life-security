import os
import sys
import json
import numpy as np
from datetime import datetime
from keras.models import Sequential
from keras.layers import Dense, LSTM, Bidirectional
from keras.preprocessing import sequence
from keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.utils import class_weight
import tensorflow as tf
from gensim.models import Word2Vec
import random
from tensorflow.keras.utils import Sequence
import myutils

os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Retrieve vulnerability mode from command-line arguments
mode = "dos"
# #mode = "overflow"
# #mode = "info"
# #mode = "bypass"
# mode = "priv"

if len(sys.argv) > 1:
    mode = sys.argv[1]

# Parameters for sample extraction
step = 5
fulllength = 100  # Reduce length to fit memory
MAX_BLOCKS = 50000  # Limit dataset size

# Word2Vec model loading
w2v_model_path = "w2v/word2vec_withString10-100-200.model"
if not os.path.isfile(w2v_model_path):
    print("Word2Vec model is missing.")
    sys.exit()

w2v_model = Word2Vec.load(w2v_model_path)
word_vectors = w2v_model.wv

# Load processed dataset from JSON
with open(f'data/plain_{mode}', 'r') as infile:
    data = json.load(infile)

print("Finished loading data at", datetime.now().strftime("%H:%M"))

allblocks = []
for r in data:
    for c in data[r]:
        commit_obj = data[r][c]
        if "files" not in commit_obj:
            continue
        for f in commit_obj["files"]:
            sourcecode = commit_obj["files"][f].get("source") or commit_obj["files"][f].get("patch", "").strip()
            if not sourcecode:
                continue

            sourcecode = myutils.stripComments(sourcecode)
            allbadparts = []

            if "changes" not in commit_obj["files"][f]:
                continue
            for change in commit_obj["files"][f]["changes"]:
                badparts = change.get("badparts", [])
                for bad in badparts:
                    pos = myutils.findposition(bad, sourcecode)
                    if -1 not in pos:
                        allbadparts.append(bad)

            if len(allbadparts) > 0:
                positions = myutils.findpositions(allbadparts, sourcecode)
                blocks = myutils.getblocks(sourcecode, positions, step, fulllength)
                allblocks.extend(blocks)

# Limit dataset size
if len(allblocks) > MAX_BLOCKS:
    allblocks = random.sample(allblocks, MAX_BLOCKS)

print("Total blocks used:", len(allblocks))
if len(allblocks) == 0:
    print("No blocks extracted. Exiting.")
    sys.exit(1)

blocks = np.array(allblocks, dtype=object)
labels = np.array([block[1] for block in blocks])

blocks_train, blocks_temp, y_train, y_temp = train_test_split(
    blocks, labels, test_size=0.3, stratify=labels, random_state=42
)

blocks_val, blocks_test, y_val, y_test = train_test_split(
    blocks_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
)

print("Train samples:", len(blocks_train))
print("Validation samples:", len(blocks_val))
print("Final test samples:", len(blocks_test))

MAX_TOKENS = 100  # Reduce input size

def blocks_to_vectors(blocks):
    X, y = [], []
    for block in blocks:
        tokens = myutils.getTokens(block[0])[:MAX_TOKENS]  # Limit tokens per sequence
        vectorlist = [word_vectors[t].tolist() for t in tokens if t in word_vectors.key_to_index and t.strip()]
        X.append(vectorlist)
        y.append(block[1])
    return X, y

TrainX, TrainY = blocks_to_vectors(blocks_train)
ValidateX, ValidateY = blocks_to_vectors(blocks_val)
FinaltestX, FinaltestY = blocks_to_vectors(blocks_test)

# Pad sequences
X_train = sequence.pad_sequences(TrainX, maxlen=fulllength, dtype="float32")
X_val = sequence.pad_sequences(ValidateX, maxlen=fulllength, dtype="float32")
X_test = sequence.pad_sequences(FinaltestX, maxlen=fulllength, dtype="float32")

print(f"{len(TrainX)} samples in the training set.")

class DataGenerator(Sequence):
    def __init__(self, X, y, batch_size=32):
        self.X, self.y, self.batch_size = X, y, batch_size

    def __len__(self):
        return int(np.ceil(len(self.X) / self.batch_size))

    def __getitem__(self, index):
        batch_X = self.X[index * self.batch_size:(index + 1) * self.batch_size]
        batch_y = self.y[index * self.batch_size:(index + 1) * self.batch_size]
        return np.array(batch_X), np.array(batch_y)

train_gen = DataGenerator(X_train, TrainY, batch_size=32)
val_gen = DataGenerator(X_val, ValidateY, batch_size=32)

# Enhanced hyperparameters
dropout = 0.3
neurons = 128
epochs = 10
batchsize = 32

# Create a more complex model
from keras.layers import BatchNormalization, Dropout

model = Sequential()
# First LSTM layer with batch normalization
model.add(Bidirectional(LSTM(neurons, dropout=dropout, recurrent_dropout=dropout, 
                             return_sequences=True),
                        input_shape=(fulllength, X_train.shape[2])))
model.add(BatchNormalization())

# Second LSTM layer
model.add(Bidirectional(LSTM(neurons//2, dropout=dropout, recurrent_dropout=dropout)))
model.add(BatchNormalization())

# Dense layers for better feature representation
model.add(Dense(neurons, activation='relu'))
model.add(Dropout(dropout))
model.add(BatchNormalization())

model.add(Dense(neurons//2, activation='relu'))
model.add(Dropout(dropout))

# Output layer
model.add(Dense(1, activation='sigmoid'))

# Compile with the same loss function
model.compile(loss=myutils.f1_loss, optimizer='adam', metrics=[myutils.f1])
print("Compiled enhanced LSTM model.")

TrainY_np = np.array(TrainY)
weights = class_weight.compute_class_weight(class_weight='balanced', classes=np.unique(TrainY_np), y=TrainY_np)
class_weights = {int(cls): weight for cls, weight in zip(np.unique(TrainY_np), weights)}

# Improved training monitoring
early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
checkpoint = ModelCheckpoint(f'model/enhanced_LSTM_model_{mode}.h5', monitor='val_loss', save_best_only=True)

# Add learning rate scheduler
from keras.callbacks import ReduceLROnPlateau
reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=3, min_lr=0.0001)

history = model.fit(train_gen, validation_data=val_gen, epochs=epochs,
                    class_weight=class_weights, callbacks=[early_stop, checkpoint, reduce_lr])

def get_pred_classes(X):
    return (model.predict(X, verbose=0) > 0.5).astype("int32")

for dataset, data_X, data_Y in [("train", X_train, TrainY_np),
                                 ("validation", X_val, np.array(ValidateY)),
                                 ("final test", X_test, np.array(FinaltestY))]:
    yhat_classes = get_pred_classes(data_X)
    print(f"Results on {dataset} set:")
    print("Accuracy:", accuracy_score(data_Y, yhat_classes))
    print("Precision:", precision_score(data_Y, yhat_classes))
    print("Recall:", recall_score(data_Y, yhat_classes))
    print("F1 score:", f1_score(data_Y, yhat_classes), "\n")

# Save final model with enhanced name
print("Saving enhanced LSTM model.")
model.save(f'model/enhanced_LSTM_model_{mode}.h5')
print("Done.")
