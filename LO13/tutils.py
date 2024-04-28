from Cryptodome.Cipher import AES
import time
import hashlib
import string
import random

def padToSize(s, len):
    return str(s).rjust(len, " ")
 
def getDummyStr(strLen):
    str_list = ['0' for i in range(strLen)]
    return ''.join(str_list)

def getRandomStr(strLen):
    str_list = [random.choice(string.digits + string.ascii_letters) for i in range(strLen-1)]
    return ''.join(str_list)+'S'

def add_to_16(value):
    while len(value) % 16 != 0:
        value += "\0"
    return str.encode(value) 

def convert(convertKey, s):
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(convertKey)+str(s)))
    return int.from_bytes(sha1.digest(), 'big', signed=False)%2

def prg(secretKey, s):
    """
    lambda -> 2*lambda +2 
    Assume s is 16-byte
    """
    secretCipher = AES.new(secretKey, AES.MODE_ECB, use_aesni=True)
    sL = secretCipher.encrypt(add_to_16(str(0)+str(s)))[:16]
    sR = secretCipher.encrypt(add_to_16(str(1)+str(s)))[:16]
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(2)+str(secretKey)+str(s)))
    tL = int.from_bytes(sha1.digest(), 'big', signed=False)%2
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(3)+str(secretKey)+str(s)))
    tR = int.from_bytes(sha1.digest(), 'big', signed=False)%2
    return sL,tL,sR,tR

def bitExtract(ind, n):
    res = [0 for i in range(n+1)]
    for i in range(n):
        res[i+1] = ind>>(n-i-1)&1
    return res

def intXor(s1, s2):
    return int(s1)^int(s2)

def strXor(s: str, k: str):
    k = (k * (len(s) // len(k) + 1))[0:len(s)]
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s, k))
 
def byteXor(b1, b2):
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)

def bytesToStr(mb):
    return mb.decode('ISO-8859-1')
    
def strToBytes(str):
    return str.encode('ISO-8859-1')

def standardHashPosition(levelKey, tag, tableLength):
    """
    Ensure the position 0 does not store elements
    """
    if tag==bytes(16):
        return random.randint(0,tableLength-1)
    sha1 = hashlib.sha1()   
    sha1.update(add_to_16(str(levelKey)+str(tag)))
    return int.from_bytes(sha1.digest(), 'big', signed=False) % tableLength

def cuckooHashPosition(levelKey, tag, tableLength):
    """
    Ensure the position 0 does not store elements
    """
    if tag==bytes(16):
        return random.randint(0,tableLength-1),random.randint(0,tableLength-1)
    levelCipher = AES.new(levelKey, AES.MODE_ECB, use_aesni=True)
    sha0 = hashlib.sha1()
    secretkey0 = levelCipher.encrypt(add_to_16(str(1)))
    sha0.update(add_to_16(str(secretkey0)+str(tag)))
    sha1 = hashlib.sha1()
    secretkey1 = levelCipher.encrypt(add_to_16(str(2)))#get_random_bytes(16)
    sha1.update(add_to_16(str(secretkey1)+str(tag)))
    return int.from_bytes(sha0.digest(), 'big', signed=False) % tableLength, int.from_bytes(sha1.digest(), 'big', signed=False) % tableLength

def standardHash(tagKV, pos, table, stash, emptyForm):
    if emptyForm in table[pos]:
        table[pos][table[pos].index(emptyForm)] = tagKV
    else:
        stash.append(tagKV)

def cuckooHash(tagKV, pos0, pos1, table, stash, posDict, thresholdKicked, emptyForm):
    ins_preservedV = tagKV
    ins_table_num = 0
    kickedPos = -1
    writePos = -1
    Loc = [pos0, pos1]
    if table[0][Loc[0]][0]==emptyForm[0]:
        table[0][Loc[0]]=ins_preservedV
        posDict[0][Loc[0]]=Loc[1]
        return
    elif table[1][Loc[1]][0]==emptyForm[0]:
        table[1][Loc[1]]=ins_preservedV
        posDict[1][Loc[1]]=Loc[0]
        return
    else:
        ins_table_num = 0
        kickedV = table[ins_table_num][Loc[ins_table_num]]
        kickedPos = Loc[ins_table_num]
        writePos = posDict[ins_table_num][Loc[ins_table_num]]

        table[ins_table_num][Loc[ins_table_num]]=ins_preservedV
        posDict[ins_table_num][Loc[ins_table_num]] = Loc[ins_table_num^1]
        ins_table_num = ins_table_num^1

    count = 0
    while count<thresholdKicked-1:
        if table[ins_table_num][writePos][0]==emptyForm[0]:
            table[ins_table_num][writePos]=kickedV
            posDict[ins_table_num][writePos]=kickedPos
            return
        else:
            tempKickedV = table[ins_table_num][writePos]
            tempKickedPos = writePos
            tempWritePos = posDict[ins_table_num][writePos]

            table[ins_table_num][writePos] = kickedV
            posDict[ins_table_num][writePos] = kickedPos # kickedPos writePos

            kickedV = tempKickedV
            kickedPos = tempKickedPos
            writePos = tempWritePos

            ins_table_num = ins_table_num^1

            count += 1
    if count==thresholdKicked-1:
        stash.append(tagKV)

if __name__=="__main__":
    import pickle
    pic = open(r'.\Result\BlockNum_{}.pkl'.format(8), 'wb')
    pickle.dump(0,pic)
    m = (bytes(16),"-1","-1")
    p = (bytes(16),"-1","-1")
    pslf = [[314,52523],[5355,424]]
    pll = [93,3242,5]
    pll.extend(pslf)
    pslf = []
    import random
    random.shuffle(pll)
    print(pll)
    print(m==p)
    print(m)
    gt = b'\x8e_\x9aY#\xf3\xc6.$\xfd\xb1\x02\xed\x10\xd1\xa7'
    tag = b'\xbdtW\x80\x98\xccG\xd5\x1e%\x9e.\xc3\xcfYA'
    print(gt)
    print(tag)
    bb = time.time()
    print(cuckooHashPosition(gt,tag,100))
    ee = time.time()
    print(ee-bb)
    #print(add_to_16(gt))

