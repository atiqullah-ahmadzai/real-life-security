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
    "priv escalation & execution": ["system", "exec", "popen"]
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

def is_line_vulnerable(line, mode):
    indicators = vulnerability_indicators_map.get(mode.lower(), [])
    for keyword in indicators:
        if keyword in line:
            simulated_diff = "- " + line
            if getBadpart(simulated_diff) is not None:
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
    for line in lines:
        vulnerablePos = is_line_vulnerable(line, mode)
        tokens = line.split()
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

        pil_color, console_text = get_colors(p, vulnerablePos, threshold, line)
        print(console_text + f"  (p={p:.3f})")
        draw.text((0, y_offset), line, fill=pil_color, font=font)
        y_offset += line_height + 4

    for i in range(1, 100):
        filename = f"demo/demo_{mode}_{i}.png"
        if not os.path.isfile(filename):
            img.save(filename)
            print(f"Saved PNG: {filename}")
            break
