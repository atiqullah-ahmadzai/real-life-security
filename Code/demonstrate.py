import myutils
from datetime import datetime
import os
import sys
from keras.models import load_model
from gensim.models import Word2Vec

def main():
    # Default parameters
    mode = "dos"
    # mode = "overflow"
    # mode = "info"
    # mode = "bypass"
    # mode = "priv"
    
    nr = "1"
    fine = ""
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    if len(sys.argv) > 2:
        nr = sys.argv[2]
    if len(sys.argv) > 3:
        fine = sys.argv[3]
    
    # Define thresholds (choose threshold2 for fine mode, else threshold1)
    threshold1 = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
    threshold2 = [0.9999, 0.999, 0.99, 0.9, 0.5, 0.1, 0.01, 0.001, 0.0001]
    threshold = threshold2 if fine == "fine" else threshold1
    
    nowformat = datetime.now().strftime("%H:%M")
    print("Current time:", nowformat)
    
    # Load the Word2Vec model
    mincount = 10
    iterationen = 100
    s = 200
    w2v = "word2vec_" + "withString" + str(mincount) + "-" + str(iterationen) + "-" + str(s)
    w2vmodel_path = os.path.join("w2v", w2v + ".model")
    if not os.path.exists(w2vmodel_path):
        print("Word2Vec model not found at", w2vmodel_path)
        sys.exit(1)
    w2v_model = Word2Vec.load(w2vmodel_path)
    
    # Load the trained LSTM model
    lstm_model_path = os.path.join("model", "LSTM_model_" + mode + ".h5")
    if not os.path.exists(lstm_model_path):
        print("LSTM model not found at", lstm_model_path)
        sys.exit(1)
    model = load_model(lstm_model_path, custom_objects={'f1_loss': myutils.f1_loss, 'f1': myutils.f1})
    
    # Read the example C source file for demonstration
    example_file = os.path.join("examples", mode + "_1.c")
    if not os.path.exists(example_file):
        print("Example file not found at", example_file)
        sys.exit(1)
    with open(example_file, 'r') as infile:
        sourcecodefull = infile.read()
    
    # Call the visualization function, passing the current mode so that vulnerability detection is mode-specific
    myutils.getblocksVisualLineByLine(mode, sourcecodefull, w2v_model, model, threshold)
    
if __name__ == "__main__":
    main()
