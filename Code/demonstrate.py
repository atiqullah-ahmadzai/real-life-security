import myutils
from datetime import datetime
import os
import sys
from keras.models import load_model
from gensim.models import Word2Vec

def main():
    # Default parameters - set overflow as default mode to catch buffer overflow issues
    mode = "dos"
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
    print(f"Analyzing for {mode} vulnerabilities...")
    
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
    
    # Try to load the enhanced model first, fall back to the original if not available
    model_paths = [
        os.path.join("model", f"enhanced_LSTM_attention_model_{mode}.h5"),
        os.path.join("model", f"enhanced_LSTM_model_{mode}.h5"),
        os.path.join("model", f"LSTM_model_{mode}.h5")
    ]
    
    model = None
    for model_path in model_paths:
        if os.path.exists(model_path):
            print(f"Loading model from {model_path}")
            try:
                model = load_model(model_path, custom_objects={'f1_loss': myutils.f1_loss, 'f1': myutils.f1})
                break
            except Exception as e:
                print(f"Error loading model {model_path}: {e}")
                continue
    
    if model is None:
        print("No suitable LSTM model found.")
        sys.exit(1)
    
    # Read the example C source file for demonstration
    example_file = os.path.join("examples", f"{mode}_{nr}.c")
    if not os.path.exists(example_file):
        print(f"Example file not found at {example_file}. Checking for generic file...")
        # Try without specifying mode
        generic_file = os.path.join("examples", f"example_{nr}.c")
        if os.path.exists(generic_file):
            example_file = generic_file
        else:
            # Look for any C file with the vulnerability type in its name
            for file in os.listdir("examples"):
                if file.endswith(".c") and (mode in file or "vulnerability" in file):
                    example_file = os.path.join("examples", file)
                    print(f"Found alternative file: {example_file}")
                    break
            else:
                print("No suitable example file found.")
                sys.exit(1)
    
    with open(example_file, 'r') as infile:
        sourcecodefull = infile.read()
    
    print(f"Analyzing file: {example_file}")
    
    
    print(f"Using detection mode: {mode}")
    

    
    # Call the word-by-word visualization function
    myutils.getblocksVisualWordByWord(mode, sourcecodefull, w2v_model, model, threshold)
    
if __name__ == "__main__":
    main()
