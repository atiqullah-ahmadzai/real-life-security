import re
import os
import builtins
import keyword
import pickle
import numpy
from keras.preprocessing import sequence
from keras import backend as K
import tensorflow as tf
from gensim.models import Word2Vec, KeyedVectors
from PIL import Image, ImageDraw, ImageFont
from termcolor import colored

###########################
# COMMENT HANDLING FUNCTIONS
###########################

def findComments(sourcecode):
    """
    Find comment areas in C code (both single-line and block comments).
    Returns a list of [start, end] positions.
    """
    pattern = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
    commentareas = []
    for match in pattern.finditer(sourcecode):
        commentareas.append([match.start(), match.end()])
    return commentareas

def stripComments(code):
    """
    Removes all C-style comments from code.
    """
    pattern = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
    return re.sub(pattern, '', code)

###########################
# POSITION FINDING FUNCTIONS
###########################

def findposition(badpart, sourcecode):
    """
    Attempts to locate the position (start and end indices) of a given badpart string in the sourcecode,
    ignoring text inside C comments.
    Returns [start, end] if found, else [-1, -1].
    """
    splitchars = ["\t", "\n", " ", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
                  "\"", "\'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&"]
    pos = 0
    matchindex = 0
    in_line_comment = False
    in_block_comment = False
    startfound = -1
    endfound = -1
    end = False

    badpart = badpart.lstrip()
    if len(badpart) < 1:
        return [-1, -1]

    while not end:
        if pos >= len(sourcecode):
            end = True
            break

        # Check for start of comments:
        if sourcecode[pos:pos+2] == "//":
            in_line_comment = True
        if sourcecode[pos:pos+2] == "/*":
            in_block_comment = True

        # End line comment at newline.
        if in_line_comment and sourcecode[pos] == "\n":
            in_line_comment = False
        # End block comment when encountering "*/"
        if in_block_comment and sourcecode[pos:pos+2] == "*/":
            in_block_comment = False
            pos += 2
            continue

        # If in any comment, skip this character.
        if in_line_comment or in_block_comment:
            pos += 1
            continue

        # Skip extra whitespace (similar to original logic)
        if sourcecode[pos] == "\n" and pos > 0 and sourcecode[pos-1] in ["\n", " "]:
            pos += 1
            continue
        if sourcecode[pos] == " " and pos > 0 and sourcecode[pos-1] == " ":
            pos += 1
            continue

        # Matching logic: if current character matches badpart[matchindex]
        if sourcecode[pos] == badpart[matchindex]:
            if matchindex == 0:
                startfound = pos
            matchindex += 1
            if matchindex == len(badpart):
                endfound = pos
                break
        else:
            # Reset match if a mismatch occurs
            matchindex = 0
            startfound = -1

        pos += 1

    if startfound == -1 or endfound == -1:
        return [-1, -1]
    return [startfound, endfound]

def findpositions(badparts, sourcecode):
    """
    For each badpart in badparts, determine its position in sourcecode.
    Returns a list of [start, end] positions (only those with valid positions).
    """
    positions = []
    for bad in badparts:
        # Remove any trailing comment markers from bad (if any)
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
        if previoussplit(sourcecode, startcontext) == -1 and nextsplit(sourcecode, endcontext) == -1:
            return None
        if toggle and previoussplit(sourcecode, startcontext) > -1:
            startcontext = previoussplit(sourcecode, startcontext)
        elif not toggle and nextsplit(sourcecode, endcontext) > -1:
            endcontext = nextsplit(sourcecode, endcontext)
        toggle = not toggle
    return [startcontext, endcontext]

def getcontext(sourcecode, focus, fulllength):
    startcontext = focus
    endcontext = focus
    if focus >= len(sourcecode):
        return None

    toggle = True
    while len(sourcecode[startcontext:endcontext]) < fulllength:
        if previoussplit(sourcecode, startcontext) == -1 and nextsplit(sourcecode, endcontext) == -1:
            return None
        if toggle and previoussplit(sourcecode, startcontext) > -1:
            startcontext = previoussplit(sourcecode, startcontext)
        elif not toggle and nextsplit(sourcecode, endcontext) > -1:
            endcontext = nextsplit(sourcecode, endcontext)
        toggle = not toggle
    return sourcecode[startcontext:endcontext]

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
                singleblock = [sourcecode[context[0]:context[1]], label]
                if not any(b[0] == singleblock[0] for b in blocks):
                    blocks.append(singleblock)
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

###########################
# DIFF-PARSING FUNCTIONS
###########################

def getBadpart(change):
    """
    Parse a diff string and return a two-element list:
      [list of removed lines (bad examples), list of added lines (good examples)]
    Returns None if no significant removal lines are found.
    """
    lines = change.split("\n")
    # Check if any line (after stripping) starts with a removal marker
    if not any(line.lstrip().startswith("-") for line in lines):
        return None

    badexamples = []
    goodexamples = []
    
    for line in lines:
        stripped_line = line.strip()
        if len(stripped_line) <= 1:
            continue  # Skip trivial or empty lines
        if stripped_line.startswith("-"):
            content = stripped_line[1:].strip()
            # Skip trivial content such as only braces or semicolons.
            if content and content not in ["{", "}", "};", ";"]:
                badexamples.append(content)
        elif stripped_line.startswith("+"):
            content = stripped_line[1:].strip()
            if content and content not in ["{", "}", "};", ";"]:
                goodexamples.append(content)
    
    if not badexamples:
        return None
    return [badexamples, goodexamples]


def getTokens(change):
    # Clean up spacing around punctuation
    for old, new in [(" .", "."), (" ,", ","), (" )", ")"), (" (", "("),
                     (" ]", "]"), (" [", "["), (" {", "{"), (" }", "}"),
                     (" :", ":"), ("- ", "-"), ("+ ", "+"), (" =", "="), ("= ", "=")]:
        change = change.replace(old, new)
    splitchars = [" ", "\t", "\n", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
                  "\"", "\'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&"]
    tokens = []
    start = 0
    for i in range(len(change)):
        if change[i] in splitchars:
            if i > start:
                token = change[start:i]
                if token:
                    tokens.append(token)
            tokens.append(change[i])
            start = i
    return tokens

def removeDoubleSeperatorsString(string):
    return "".join(removeDoubleSeperators(getTokens(string)))

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
    for t in tokens:
        if t not in ["\n", " "]:
            return False
    return True

def is_builtin(name):
    # For C, there is no direct equivalent to Python builtins.
    return False

def is_keyword(name):
    # Define a set of common C keywords.
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
    """
    Extracts blocks from safe code portions.
    Returns a list of blocks, where each block is [code snippet, label=1].
    """
    blocks = []
    if goodpositions:
        for pos in goodpositions:
            # Ensure pos is valid and nonempty
            if pos and pos[0] < pos[1]:
                focus = pos[0]
                while focus < pos[1]:
                    context = getcontext(sourcecode, focus, fulllength)
                    if context and context.strip():
                        singleblock = [context, 1]
                        if not any(b[0] == singleblock[0] for b in blocks):
                            blocks.append(singleblock)
                    ns = nextsplit(sourcecode, focus + 15)
                    if ns > -1 and ns < pos[1]:
                        focus = ns
                    else:
                        break
    return blocks

###########################
# LOSS, PREDICTION, VISUALIZATION
###########################

def f1_loss(y_true, y_pred):
    # Cast both y_true and y_pred to float32
    y_true = K.cast(y_true, 'float32')
    y_pred = K.cast(y_pred, 'float32')
    tp = K.sum(y_true * y_pred, axis=0)
    tn = K.sum((1 - y_true) * (1 - y_pred), axis=0)
    fp = K.sum((1 - y_true) * y_pred, axis=0)
    fn = K.sum(y_true * (1 - y_pred), axis=0)
    p = tp / (tp + fp + K.epsilon())
    r = tp / (tp + fn + K.epsilon())
    f1 = 2 * p * r / (p + r + K.epsilon())
    f1 = tf.where(tf.math.is_nan(f1), tf.zeros_like(f1), f1)
    return 1 - K.mean(f1)

def f1(y_true, y_pred):
    y_true = K.cast(y_true, 'float32')
    y_pred = K.cast(y_pred, 'float32')
    def recall(y_true, y_pred):
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
        return true_positives / (possible_positives + K.epsilon())
    def precision(y_true, y_pred):
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
        return true_positives / (predicted_positives + K.epsilon())
    prec = precision(y_true, y_pred)
    rec = recall(y_true, y_pred)
    return 2 * ((prec * rec) / (prec + rec + K.epsilon()))

def predict(vectorlist, model):
    if vectorlist:
        one = numpy.array([vectorlist])
        max_length = 200
        one = sequence.pad_sequences(one, maxlen=max_length)
        yhat_probs = model.predict(one, verbose=0)
        prediction = int(yhat_probs[0][0] * 100000) * 0.00001
        return prediction
    else:
        return -1

# (Optional) getblocksVisual and dataset retrieval functions remain largely unchanged,
# but you can update them further if your C-code visualization needs differ.

def getIdentifiers(mode, nr):
    # This function remains unchanged.
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
    # Additional modes follow...
    result = [rep, com, myfile]
    return result

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
        print("Rep found", repfound)
    elif not comfound:
        print("Com found", comfound)
    elif not filefound:
        print("File found", filefound)
    return []

def getblocksVisual(mode, sourcecode, badpositions, commentareas, fulllength, step, nr, w2v_model, model, threshold, name):
    from PIL import Image, ImageDraw, ImageFont
    import os

    # Create a transparent image (RGBA with full transparency)
    def create_transparent_image(width, height):
        return Image.new('RGBA', (width, height), (255, 255, 255, 0))
    
    # Load default font and measure text using getbbox()
    font = ImageFont.load_default()
    def get_text_size(text):
        if not text:
            return (0, 0)
        bbox = font.getbbox(text)
        width = bbox[2] - bbox[0]
        height = bbox[3] - bbox[1]
        return (width, height)
    
    word_vectors = w2v_model.wv

    # Estimate image dimensions based on the number of lines in the source code.
    lines = sourcecode.count("\n") + 1
    base_line_height = get_text_size("A")[1] or 12
    img_height = (base_line_height + 5) * lines + 50  # some padding
    img_width = 2000

    img = create_transparent_image(img_width, img_height)
    draw = ImageDraw.Draw(img)

    xpos, ypos = 0, 0
    focus, lastfocus = 0, 0

    # Process the source code in segments
    while True:
        if focus > len(sourcecode):
            break

        # Adjust focus based on comment areas
        comment = False
        for com in commentareas:
            if (focus >= com[0] and focus <= com[1] and lastfocus >= com[0] and lastfocus < com[1]):
                focus = com[1]
                comment = True
            elif (focus > com[0] and focus <= com[1] and lastfocus < com[0]):
                focus = com[0]
                comment = False
            elif (lastfocus >= com[0] and lastfocus < com[1] and focus > com[1]):
                focus = com[1]
                comment = True

        segment = sourcecode[lastfocus:focus]
        if not segment:
            if focus < len(sourcecode):
                lastfocus = focus
                focus += step
            else:
                break
            continue

        # Default color assignment
        seg_color = "grey" if comment else "black"
        p = -1  # model's predicted probability for the current segment
        vulnerablePos = False

        # If not in a comment, try to compute a prediction
        if not comment:
            middle = lastfocus + round(0.5 * (focus - lastfocus))
            context = getcontextPos(sourcecode, middle, fulllength)
            if context is not None:
                # Determine if the context overlaps any vulnerable region
                vulnerablePos = any(
                    (context[0] > bp[0] and context[0] <= bp[1]) or
                    (context[1] > bp[0] and context[1] <= bp[1]) or
                    (context[0] <= bp[0] and context[1] >= bp[1])
                    for bp in badpositions
                )
                text_segment = sourcecode[context[0]:context[1]].replace("\n", " ")
                token = getTokens(text_segment)
                vectorlist = []
                for t in token:
                    if t in word_vectors.key_to_index and t.strip():
                        vectorlist.append(word_vectors[t].tolist())
                if vectorlist:
                    p = predict(vectorlist, model)  # original probability (likely near 1.0)
                    # Calibrate the probability (subtract an offset to counter overprediction)
                    calibration_offset = 0.2
                    adjusted_p = p - calibration_offset
                    if adjusted_p < 0:
                        adjusted_p = 0.0
                    # Print debug info showing both original and adjusted probabilities.
                    print(f"[DEBUG] Snippet => p={p:.4f}, adjusted_p={adjusted_p:.4f}, Vulnerable? {vulnerablePos}")
                    
                    # Revised color logic based on adjusted probability:
                    if vulnerablePos:
                        if adjusted_p > 0.5:
                            seg_color = "red"      # True Positive
                        else:
                            seg_color = "orange"   # False Negative
                    else:
                        if adjusted_p > 0.5:
                            seg_color = "purple"   # False Positive
                        else:
                            seg_color = "green"    # True Negative
                    print(f"       => Marking color {seg_color}.")
        
        # Draw the segment on the image; split by newline to avoid breaking a single line arbitrarily.
        segment_lines = segment.split("\n")
        for idx, line_text in enumerate(segment_lines):
            if idx > 0:
                xpos = 0
                text_w, text_h = get_text_size(line_text)
                ypos += text_h if text_h > 0 else base_line_height
            if line_text:
                draw.text((xpos, ypos), line_text, fill=seg_color, font=font)
                text_w, _ = get_text_size(line_text)
                xpos += text_w
        # After drawing the segment, reset xpos and move down one line.
        xpos = 0
        ypos += base_line_height

        # Update focus indices: use newline in the upcoming text or nextsplit()
        if "\n" in sourcecode[focus+1:focus+7]:
            newline_index = sourcecode[focus+1:focus+7].find("\n")
            lastfocus = focus
            focus = focus + newline_index + 1
        else:
            next_pos = nextsplit(sourcecode, focus + step)
            if next_pos > -1:
                lastfocus = focus
                focus = next_pos
            else:
                if focus < len(sourcecode):
                    lastfocus = focus
                    focus = len(sourcecode)
                else:
                    break

    # Save the resulting image with a unique filename.
    for i in range(1, 100):
        filename = f"demo_{mode}_{i}_{name}.png"
        if not os.path.isfile(filename):
            img.save(filename)
            print(f"Saved PNG: {filename}")
            break

    return []

