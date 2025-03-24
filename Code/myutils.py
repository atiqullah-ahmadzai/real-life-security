import re
import os
import pickle
import numpy as np
from keras.preprocessing import sequence
from keras import backend as K
import tensorflow as tf
from gensim.models import Word2Vec, KeyedVectors
from PIL import Image, ImageDraw, ImageFont
from termcolor import colored

vulnerability_indicators_map = {
    "dos": ["sleep", "kill", "fork", "exit"],
    "overflow": ["strcpy", "gets", "sprintf"],
    "infor": ["printf", "snprintf"],
    "bypass": ["memcmp", "strcmp"],
    "priv": ["system", "exec", "popen"]
}


def findComments(sourcecode):
    pattern = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
    return [[m.start(), m.end()] for m in pattern.finditer(sourcecode)]

def stripComments(code):
    pattern = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
    return re.sub(pattern, '', code)

def findposition(badpart, sourcecode):

    splitchars = ["\t", "\n", " ", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
                  "\"", "\'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&"]
    pos = 0
    matchindex = 0
    in_line_comment = False
    in_block_comment = False
    startfound = -1
    endfound = -1

    badpart = badpart.lstrip()
    if not badpart:
        return [-1, -1]

    while pos < len(sourcecode):
        # Check for comment start markers
        if sourcecode[pos:pos+2] == "//":
            in_line_comment = True
        if sourcecode[pos:pos+2] == "/*":
            in_block_comment = True

        # End comments appropriately
        if in_line_comment and sourcecode[pos] == "\n":
            in_line_comment = False
        if in_block_comment and sourcecode[pos:pos+2] == "*/":
            in_block_comment = False
            pos += 2
            continue

        # Skip characters within comments
        if in_line_comment or in_block_comment:
            pos += 1
            continue

        # Match the badpart character by character
        if sourcecode[pos] == badpart[matchindex]:
            if matchindex == 0:
                startfound = pos
            matchindex += 1
            if matchindex == len(badpart):
                endfound = pos
                return [startfound, endfound]
        else:
            matchindex = 0
            startfound = -1

        pos += 1

    return [-1, -1]

def findpositions(badparts, sourcecode):
 
    positions = []
    for bad in badparts:
        if "#" in bad:
            bad = bad.split("#")[0]
        pos = findposition(bad, sourcecode)
        if pos != [-1, -1]:
            positions.append(pos)
    return positions

def nextsplit(sourcecode, focus):
    splitchars = [" ", "\t", "\n", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
                  "\"", "\'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&"]
    for pos in range(focus + 1, len(sourcecode)):
        if sourcecode[pos] in splitchars:
            return pos
    return -1

def previoussplit(sourcecode, focus):
    splitchars = [" ", "\t", "\n", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
                  "\"", "\'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&"]
    pos = focus - 1
    while pos >= 0:
        if sourcecode[pos] in splitchars:
            return pos
        pos -= 1
    return -1

def getcontextPos(sourcecode, focus, fulllength):
    startcontext = focus
    endcontext = focus
    if focus >= len(sourcecode):
        return None
    toggle = True
    while len(sourcecode[startcontext:endcontext]) < fulllength:
        prev = previoussplit(sourcecode, startcontext)
        nxt = nextsplit(sourcecode, endcontext)
        if prev == -1 and nxt == -1:
            return None
        if toggle and prev > -1:
            startcontext = prev
        elif not toggle and nxt > -1:
            endcontext = nxt
        toggle = not toggle
    return [startcontext, endcontext]

def getcontext(sourcecode, focus, fulllength):
    pos = getcontextPos(sourcecode, focus, fulllength)
    return sourcecode[pos[0]:pos[1]] if pos else None

def getblocks(sourcecode, badpositions, step, fulllength):
    blocks = []
    focus = 0
    lastfocus = 0
    while True:
        if focus > len(sourcecode):
            break
        focusarea = sourcecode[lastfocus:focus]
        if focusarea != "\n":
            middle = lastfocus + round(0.5 * (focus - lastfocus))
            context = getcontextPos(sourcecode, middle, fulllength)
            if context is not None:
                vulnerablePos = any((context[0] > bp[0] and context[0] <= bp[1]) or
                                    (context[1] > bp[0] and context[1] <= bp[1]) or
                                    (context[0] <= bp[0] and context[1] >= bp[1])
                                    for bp in badpositions)
                label = 0 if vulnerablePos else 1
                block_snippet = sourcecode[context[0]:context[1]]
                if not any(b[0] == block_snippet for b in blocks):
                    blocks.append([block_snippet, label])
        if "\n" in sourcecode[focus+1:focus+7]:
            lastfocus = focus
            newline_index = sourcecode[focus+1:focus+7].find("\n")
            focus = focus + 1 + newline_index
        else:
            ns = nextsplit(sourcecode, focus+step)
            if ns > -1:
                lastfocus = focus
                focus = ns
            else:
                if focus < len(sourcecode):
                    lastfocus = focus
                    focus = len(sourcecode)
                else:
                    break
    return blocks

def getBadpart(change):
    lines = change.split("\n")
    if not any(line.lstrip().startswith("-") for line in lines):
        return None

    badexamples = []
    goodexamples = []
    for line in lines:
        stripped_line = line.strip()
        if len(stripped_line) <= 1:
            continue
        if stripped_line.startswith("-"):
            content = stripped_line[1:].strip()
            if content and content not in ["{", "}", "};", ";"]:
                badexamples.append(content)
        elif stripped_line.startswith("+"):
            content = stripped_line[1:].strip()
            if content and content not in ["{", "}", "};", ";"]:
                goodexamples.append(content)
    if not badexamples:
        return None
    return [badexamples, goodexamples]

def getTokens(code):
    tokens = re.findall(r'\w+|[^\s\w]', code, re.UNICODE)
    return tokens

def removeDoubleSeperatorsString(string):
    tokens = getTokens(string)
    return "".join(removeDoubleSeperators(tokens))

def removeDoubleSeperators(tokenlist):
    newtokens = []
    last = ""
    for token in tokenlist:
        if token == "\n":
            token = " "
        if token == " " and last == " ":
            continue
        newtokens.append(token)
        last = token
    return newtokens

def isEmpty(code):
    tokens = getTokens(stripComments(code))
    return all(t in ["\n", " "] for t in tokens)

def is_builtin(name):
    return False

def is_keyword(name):
    c_keywords = {"auto", "break", "case", "char", "const", "continue", "default", "do", 
                  "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", 
                  "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", 
                  "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", 
                  "while", "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic", 
                  "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local"}
    return name in c_keywords

def removeTripleN(tokenlist):
    newtokens = []
    secondlast = ""
    last = ""
    for token in tokenlist:
        if secondlast == "\n" and last == "\n" and token == "\n":
            continue
        newtokens.append(token)
        secondlast, last = last, token
    return newtokens

def getgoodblocks(sourcecode, goodpositions, fulllength):
    blocks = []
    if goodpositions:
        for pos in goodpositions:
            if pos and pos[0] < pos[1]:
                focus = pos[0]
                while focus < pos[1]:
                    context = getcontext(sourcecode, focus, fulllength)
                    if context and context.strip():
                        block_snippet = context
                        if not any(b[0] == block_snippet for b in blocks):
                            blocks.append([block_snippet, 1])
                    ns = nextsplit(sourcecode, focus + 15)
                    if ns > -1 and ns < pos[1]:
                        focus = ns
                    else:
                        break
    return blocks


def f1_loss(y_true, y_pred):
    """
    Custom F1 loss function.
    """
    y_true = K.cast(y_true, 'float32')
    y_pred = K.cast(y_pred, 'float32')
    tp = K.sum(y_true * y_pred, axis=0)
    tn = K.sum((1 - y_true) * (1 - y_pred), axis=0)
    fp = K.sum((1 - y_true) * y_pred, axis=0)
    fn = K.sum(y_true * (1 - y_pred), axis=0)
    precision = tp / (tp + fp + K.epsilon())
    recall = tp / (tp + fn + K.epsilon())
    f1 = 2 * precision * recall / (precision + recall + K.epsilon())
    f1 = tf.where(tf.math.is_nan(f1), tf.zeros_like(f1), f1)
    return 1 - K.mean(f1)

def f1(y_true, y_pred):
    y_true = K.cast(y_true, 'float32')
    y_pred = K.cast(y_pred, 'float32')
    def recall(y_true, y_pred):
        tp = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
        return tp / (possible_positives + K.epsilon())
    def precision(y_true, y_pred):
        tp = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
        return tp / (predicted_positives + K.epsilon())
    prec = precision(y_true, y_pred)
    rec = recall(y_true, y_pred)
    return 2 * ((prec * rec) / (prec + rec + K.epsilon()))

def predict(vectorlist, model):
    if vectorlist:
        one = np.array([vectorlist])
        max_length = 200
        one = sequence.pad_sequences(one, maxlen=max_length)
        yhat_probs = model.predict(one, verbose=0)
        return float(yhat_probs[0][0])
    else:
        return -1

def getIdentifiers(mode, nr):
    if mode == "sql":
        if nr == "1":
            rep = "instacart/lore"
            com = "a0a5fd945a8bf128d4b9fb6a3ebc6306f82fa4d0"
            myfile = "/lore/io/connection.py"
        elif nr == "2":
            rep = "uktrade/export-wins-data"
            com = "307587cc00d2290a433bf74bd305aecffcbb05a2"
            myfile = "/wins/views/flat_csv.py"
        elif nr == "3":
            rep = "onewyoming/onewyoming"
            com = "54fc7b076fda2de74eeb55e6b75b28e09ef231c2"
            myfile = "/experimental/python/buford/model/visitor.py"
    return [rep, com, myfile]

def getFromDataset(identifying, data):
    result = []
    rep, com, myfile = identifying
    rep_url = "https://github.com/" + rep
    repfound = False
    comfound = False
    filefound = False
    for r in data:
        if rep_url == r:
            repfound = True
            for commit_obj in data[r]:
                sha = commit_obj.get("commit", None)
                if sha == com:
                    comfound = True
                    if "files" in commit_obj:
                        for f in commit_obj["files"]:
                            if myfile == f:
                                filefound = True
                                if "source" in commit_obj["files"][f]:
                                    allbadparts = []
                                    sourcecode = commit_obj["files"][f]["source"]
                                    sourcefull = commit_obj["files"][f]["sourceWithComments"]
                                    for change in commit_obj["files"][f]["changes"]:
                                        badparts = change["badparts"]
                                        if len(badparts) < 20:
                                            for bad in badparts:
                                                pos = findposition(bad, sourcecode)
                                                if -1 not in pos:
                                                    allbadparts.append(bad)
                                    result.append(sourcefull)
                                    result.append(allbadparts)
                                    return result
    if not repfound:
        print("Repository not found:", rep)
    elif not comfound:
        print("Commit not found:", com)
    elif not filefound:
        print("File not found:", myfile)
    return []

def get_colors(p, vulnerablePos, threshold, text_segment):
    if vulnerablePos:
        if p > 0.5:
            pil_color = "royalblue"
            console_text = colored(text_segment, 'cyan')
        else:
            pil_color = "violet"
            console_text = colored(text_segment, 'magenta')
    else:
        if p > threshold[0]:
            pil_color = "darkred"
        elif p > threshold[1]:
            pil_color = "red"
        elif p > threshold[2]:
            pil_color = "darkorange"
        elif p > threshold[3]:
            pil_color = "orange"
        elif p > threshold[4]:
            pil_color = "gold"
        elif p > threshold[5]:
            pil_color = "yellow"
        elif p > threshold[6]:
            pil_color = "LightBlue"
        elif p > threshold[7]:
            pil_color = "SkyBlue"
        elif p > threshold[8]:
            pil_color = "Blue"
        else:
            pil_color = "DarkBlue"

        if p > 0.8:
            console_text = colored(text_segment, 'red')
        elif p > 0.5:
            console_text = colored(text_segment, 'yellow')
        else:
            console_text = colored(text_segment, 'blue')

    return pil_color, console_text

def is_import_statement(line):
    """Check if a line is an import statement"""
    line = line.strip().lower()
    return (line.startswith('import ') or 
            line.startswith('from ') or 
            line.startswith('#include') or
            line.startswith('using namespace') or
            line.startswith('require'))

def is_comment(line):
    """Check if a line is only a comment"""
    line = line.strip()
    return (line.startswith('//') or 
            line.startswith('#') or 
            line.startswith('/*') or 
            (line.startswith('*') and not line.startswith('*/')))

def is_print_statement(line):
    """Check if a line is a print statement"""
    line = line.strip().lower()
    return (line.startswith('print(') or 
            line.startswith('printf(') or 
            line.startswith('cout <<') or 
            line.startswith('console.log(') or
            'system.out.print' in line)

def is_empty_or_whitespace(line):
    """Check if a line is empty or just whitespace"""
    return not line.strip()

def detect_code_element_type(line, mode):
    """Classify a line of code"""
    if is_empty_or_whitespace(line):
        return "empty"
    if is_comment(line):
        return "comment"
    if is_import_statement(line):
        return "import"
    if is_print_statement(line):
        return "print"
    
    # Check for vulnerable patterns
    indicators = vulnerability_indicators_map.get(mode.lower(), [])
    for keyword in indicators:
        if keyword in line.lower():
            return "vulnerable_candidate"
            
    return "code"

def is_line_vulnerable(line, mode):
    """Improved function to detect if a line might be vulnerable"""
    # Skip non-code elements
    if (is_empty_or_whitespace(line) or 
        is_comment(line) or 
        is_import_statement(line) or
        is_print_statement(line)):
        return False
        
    # Look for vulnerability indicators based on mode
    indicators = vulnerability_indicators_map.get(mode.lower(), [])
    for keyword in indicators:
        if keyword in line.lower():
            # Check for unsafe usage patterns
            if mode == "overflow" and keyword == "strcpy":
                return "buffer" in line.lower() and not "strncpy" in line.lower()
            elif mode == "dos" and keyword == "sleep":
                return "while" in line.lower() or "for" in line.lower()
            elif keyword in line:
                # For other cases, just detecting the keyword might be enough
                # but we could add more nuanced detection
                return True
    return False

def getblocksVisualLineByLine(mode, sourcecode, w2v_model, model, threshold, max_length=100):
    font = ImageFont.load_default()
    lines = sourcecode.splitlines()

    sample_bbox = font.getbbox("A")
    line_height = (sample_bbox[3] - sample_bbox[1]) if sample_bbox else 12
    img_height = (line_height + 4) * len(lines) + 50
    img_width = 1000

    img = Image.new('RGBA', (img_width, img_height), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)
    y_offset = 0

    # Add a legend
    legend_items = [
        ("Very High Risk", "darkred"),
        ("High Risk", "red"),
        ("Medium Risk", "darkorange"),
        ("Low Risk", "yellow"),
        ("Very Low Risk", "lightblue"),
        ("Import/Comment", "gray")
    ]
    
    legend_x = 10
    for text, color in legend_items:
        draw.rectangle((legend_x, 5, legend_x + 15, 20), fill=color)
        draw.text((legend_x + 20, 5), text, fill="black", font=font)
        legend_x += 150

    y_offset = 30  # Start below the legend
    
    for line in lines:
        element_type = detect_code_element_type(line, mode)
        vulnerablePos = is_line_vulnerable(line, mode)
        
        if element_type in ["empty", "comment", "import", "print"]:
            # Set default prediction for non-code elements
            p = 1.0 if element_type == "comment" else 0.0
            pil_color = "gray"
            console_text = colored(line, 'dark_grey')
            print("No")
        else:
            print("Yes")
            # Process actual code for vulnerability prediction
            tokens = getTokens(line)
            vectorlist = []
            for token in tokens:
                if token in w2v_model.wv.key_to_index:
                    vectorlist.append(w2v_model.wv[token].tolist())

            p = 0.0
            if vectorlist:
                arr = np.array([vectorlist])
                arr = sequence.pad_sequences(arr, maxlen=max_length, dtype='float32')
                yhat_probs = model.predict(arr, verbose=0)
                p = float(yhat_probs[0][0])
            
            # Adjust the color scheme for better visualization
           
            if vulnerablePos:
                if p > 0.5:  # Model incorrectly classifies vulnerable code as safe
                    pil_color = "royalblue"
                    console_text = colored(line, 'cyan')
                else:  # Model correctly identifies vulnerable code
                    pil_color = "darkred"
                    console_text = colored(line, 'red')
            else:
                if p < 0.2:
                    pil_color = "darkred"  # Very high risk
                elif p < 0.4:
                    pil_color = "red"  # High risk
                elif p < 0.6:
                    pil_color = "darkorange"  # Medium risk
                elif p < 0.8:
                    pil_color = "orange"  # Medium-low risk
                elif p < 0.9:
                    pil_color = "gold"  # Low risk
                else:
                    pil_color = "darkgreen"  # Very low risk (safe)
                
                if p < 0.5:
                    console_text = colored(line, 'red')
                elif p < 0.8:
                    console_text = colored(line, 'yellow')
                else:
                    console_text = colored(line, 'green')

        print(console_text + f"  (p={p:.3f})")
        draw.text((0, y_offset), line, fill=pil_color, font=font)
        y_offset += line_height + 4

    for i in range(1, 100):
        filename = f"demo/demo_{mode}_{i}.png"
        if not os.path.isfile(filename):
            img.save(filename)
            print(f"Saved PNG: {filename}")
            break

def getblocksVisualWordByWord(mode, sourcecode, w2v_model, model, threshold, max_length=100):
    font = ImageFont.load_default()
    lines = sourcecode.splitlines()

    sample_bbox = font.getbbox("A")
    line_height = (sample_bbox[3] - sample_bbox[1]) if sample_bbox else 12
    img_height = (line_height + 4) * len(lines) + 50
    img_width = 1200

    img = Image.new('RGBA', (img_width, img_height), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)
    y_offset = 0

    # Add a legend
    legend_items = [
        ("Very High Risk", "darkred"),
        ("High Risk", "red"),
        ("Medium Risk", "darkorange"),
        ("Low Risk", "yellow"),
        ("Very Low Risk", "lightblue"),
        ("Safe", "darkgreen")
    ]
    
    legend_x = 10
    for text, color in legend_items:
        draw.rectangle((legend_x, 5, legend_x + 15, 20), fill=color)
        draw.text((legend_x + 20, 5), text, fill="black", font=font)
        legend_x += 150

    y_offset = 30  # Start below the legend
    
    for line_idx, line in enumerate(lines):
        if not line.strip():  # Handle empty lines
            print()
            y_offset += line_height + 4
            continue
            
        x_offset = 0
        all_words = re.findall(r'\w+|[^\s\w]', line)
        colored_line = ""
        
        # First analyze the entire line to get context
        line_tokens = getTokens(line)
        line_vectors = []
        for token in line_tokens:
            if token in w2v_model.wv.key_to_index:
                line_vectors.append(w2v_model.wv[token].tolist())
        
        # Get line-level prediction for context
        line_pred = 0.5  # Default neutral value
        if line_vectors:
            try:
                arr = np.array([line_vectors])
                arr = sequence.pad_sequences(arr, maxlen=max_length, dtype='float32')
                line_pred = float(model.predict(arr, verbose=0)[0][0])
            except Exception as e:
                print(f"Error predicting line: {e}")
        
        # Check if line contains vulnerability indicators
        is_vulnerable_line = False
        indicators = vulnerability_indicators_map.get(mode.lower(), [])
        for keyword in indicators:
            if keyword.lower() in line.lower():
                is_vulnerable_line = True
                break
        
        # Process each word
        for word in all_words:
            if not word.strip():
                x_offset += font.getbbox(word)[2] if hasattr(font, 'getbbox') else font.getsize(word)[0]
                colored_line += word
                continue
                
            # Special handling for known vulnerability indicators
            is_indicator = False
            for keyword in indicators:
                if keyword.lower() == word.lower():
                    p = 0.1  # High risk for vulnerability indicators
                    is_indicator = True
                    print(f"{word} (vulnerability indicator, p={p:.3f})", end=" ")
                    break
            
            # Process word for vulnerability prediction if not an indicator
            if not is_indicator:
                if word in w2v_model.wv.key_to_index:
                    # For word-level prediction, use a combination of the word's vector 
                    # and the line-level prediction for better context
                    
                    # Get the word's prediction
                    word_vector = w2v_model.wv[word].tolist()
                    
                    # Create a small context with just this word
                    context_size = 3
                    word_idx = line_tokens.index(word) if word in line_tokens else -1
                    
                    if word_idx >= 0:
                        # Extract a small window of tokens around this word
                        start_idx = max(0, word_idx - context_size)
                        end_idx = min(len(line_tokens), word_idx + context_size + 1)
                        context_vectors = []
                        
                        for i in range(start_idx, end_idx):
                            token = line_tokens[i]
                            if token in w2v_model.wv.key_to_index:
                                context_vectors.append(w2v_model.wv[token].tolist())
                        
                        # If we have context, use it for prediction
                        if context_vectors:
                            try:
                                arr = np.array([context_vectors])
                                arr = sequence.pad_sequences(arr, maxlen=max_length, dtype='float32')
                                p = float(model.predict(arr, verbose=0)[0][0])
                            except Exception as e:
                                print(f"Error predicting context: {e}")
                                # Fall back to line prediction
                                p = line_pred
                        else:
                            # If no context, use the line prediction
                            p = line_pred
                    else:
                        # If word not found in tokens (shouldn't happen), use line prediction
                        p = line_pred
                        
                    # Adjust prediction based on line context
                    if is_vulnerable_line:
                        # If line is flagged as vulnerable, make the prediction more conservative
                        p = min(p, 0.7)  # Cap at 0.7 to indicate some risk
                        
                    print(f"{word} (p={p:.3f})", end=" ")
                else:
                    print(f"Unknown word: {word}", end=" ")
                    # Use a more conservative value for unknown words in vulnerable lines
                    p = 0.5 if is_vulnerable_line else 0.7
            
            # Determine colors based on prediction score
            if p < 0.2:
                pil_color = "darkred"  # Very high risk
                console_color = 'red'
            elif p < 0.4:
                pil_color = "red"  # High risk
                console_color = 'red'
            elif p < 0.6:
                pil_color = "darkorange"  # Medium risk
                console_color = 'yellow'
            elif p < 0.8:
                pil_color = "orange"  # Medium-low risk
                console_color = 'yellow'
            elif p < 0.9:
                pil_color = "gold"  # Low risk
                console_color = 'green'
            else:
                pil_color = "darkgreen"  # Very low risk (safe)
                console_color = 'green'
            
            # Draw the word on the image with the appropriate color
            draw.text((x_offset, y_offset), word, fill=pil_color, font=font)
            
            # Calculate next x position
            word_width = font.getbbox(word)[2] if hasattr(font, 'getbbox') else font.getsize(word)[0]
            x_offset += word_width
            
            # Add colored text to console output
            colored_line += colored(word, console_color)
            
            # Add space after word (except for punctuation)
            if not re.match(r'[^\w\s]', word):
                draw.text((x_offset, y_offset), " ", fill="black", font=font)
                x_offset += font.getbbox(" ")[2] if hasattr(font, 'getbbox') else font.getsize(" ")[0]
                colored_line += " "
        
        # Print the colored line
        print(colored_line)
        y_offset += line_height + 4

    # Save the image
    os.makedirs("demo", exist_ok=True)
    for i in range(1, 100):
        filename = f"demo/demo_wordbyword_{mode}_{i}.png"
        if not os.path.isfile(filename):
            img.save(filename)
            print(f"Saved PNG: {filename}")
            break

def getblocksVisual(mode, sourcecode, badpositions, commentareas, fulllength, step, nr, w2v_model, model, threshold, name):
    """
    Visual representation of code blocks with vulnerability highlighting.
    Creates an image file with color-coded source code based on vulnerability prediction scores.
    """
    word_vectors = w2v_model.wv
    
    ypos = 0
    xpos = 0
    
    lines = (sourcecode.count("\n"))
    img = Image.new('RGBA', (2000, 11*(lines+1)))
    color = "white"
    
    blocks = []
     
    focus = 0
    lastfocus = 0
    
    string = ""
    
    trueP = False
    falseP = False
    
    while True:
        if focus > len(sourcecode):
            break
        
        comment = False
        for com in commentareas:
            if (focus >= com[0] and focus <= com[1] and lastfocus >= com[0] and lastfocus < com[1]):
                focus = com[1]
                comment = True
            if (focus > com[0] and focus <= com[1] and lastfocus < com[0]):
                focus = com[0]
                comment = False
            elif (lastfocus >= com[0] and lastfocus < com[1] and focus > com[1]):
                focus = com[1]
                comment = True
    
        focusarea = sourcecode[lastfocus:focus]
   
        if focusarea == "\n":
            string = string + "\n"
        else:
            if comment:
                color = "grey"
                string = string + colored(focusarea, 'grey')
            else:
                middle = lastfocus + round(0.5 * (focus - lastfocus))
                context = getcontextPos(sourcecode, middle, fulllength)
                
                if context is not None:
                    vulnerablePos = False
                    for bad in badpositions:
                        if ((context[0] > bad[0] and context[0] <= bad[1]) or 
                            (context[1] > bad[0] and context[1] <= bad[1]) or 
                            (context[0] <= bad[0] and context[1] >= bad[1])):
                            vulnerablePos = True
                            
                    predictionWasMade = False
                    text = sourcecode[context[0]:context[1]].replace("\n", " ")
                    token = getTokens(text)
                    if len(token) > 1:
                        vectorlist = []
                        for t in token:
                            if t in word_vectors.key_to_index and t != " ":
                                vector = w2v_model.wv[t]
                                vectorlist.append(vector.tolist())
                                
                        if len(vectorlist) > 0:
                            p = predict(vectorlist, model)
                            if p >= 0:
                                predictionWasMade = True
                                
                                if vulnerablePos:
                                    if p > 0.5:
                                        color = "royalblue"
                                        string = string + colored(focusarea, 'cyan')
                                    else:
                                        string = string + colored(focusarea, 'magenta')
                                        color = "violet"
                                else:
                                    if p > threshold[0]:
                                        color = "darkred"
                                    elif p > threshold[1]:
                                        color = "red"
                                    elif p > threshold[2]:
                                        color = "darkorange"
                                    elif p > threshold[3]:
                                        color = "orange"
                                    elif p > threshold[4]:
                                        color = "gold"
                                    elif p > threshold[5]:
                                        color = "yellow"
                                    elif p > threshold[6]:
                                        color = "GreenYellow"
                                    elif p > threshold[7]:
                                        color = "LimeGreen"
                                    elif p > threshold[8]:
                                        color = "Green"
                                    else:
                                        color = "DarkGreen"
                            
                                    if p > 0.8:
                                        string = string + colored(focusarea, 'red')
                                    elif p > 0.5:
                                        string = string + colored(focusarea, 'yellow')
                                    else:
                                        string = string + colored(focusarea, 'green')
                                        
                    if not predictionWasMade:
                        string = string + focusarea
                else:
                    string = string + focusarea
            
        try:
            if len(focusarea) > 0:
                d = ImageDraw.Draw(img)
                if focusarea[0] == "\n":
                    ypos = ypos + 11
                    xpos = 0
                    d.text((xpos, ypos), focusarea[1:], fill=color)
                    if hasattr(d, 'textbbox'):
                        xpos = xpos + d.textbbox((0, 0), focusarea)[2]
                    else:
                        xpos = xpos + d.textsize(focusarea)[0]
                else:
                    d.text((xpos, ypos), focusarea, fill=color)
                    if hasattr(d, 'textbbox'):
                        xpos = xpos + d.textbbox((0, 0), focusarea)[2]
                    else:
                        xpos = xpos + d.textsize(focusarea)[0]
        except Exception as e:
            print(e)

        if "\n" in sourcecode[focus+1:focus+7]:
            lastfocus = focus
            newline_index = sourcecode[focus+1:focus+7].find("\n")
            focus = focus + 1 + newline_index
        else:
            if nextsplit(sourcecode, focus+step) > -1:
                lastfocus = focus
                focus = nextsplit(sourcecode, focus+step)
            else:
                if focus < len(sourcecode):
                    lastfocus = focus
                    focus = len(sourcecode)
                else:
                    break

    # Create demo directory if it doesn't exist
    os.makedirs("demo", exist_ok=True)
    
    for i in range(1, 100):
        filename = f'demo/demo_{mode}_{i}_{name}.png'
        if not os.path.isfile(filename):
            img.save(filename)
            print(f"Saved PNG: {filename}")
            break
    
    return blocks
