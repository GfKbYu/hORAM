import math
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import hashlib
import random
import string

def computePosOfHash(secretKey, virAddr, bin_num_each_table):
    return hash(str(secretKey)+str(virAddr)) % bin_num_each_table

def computeRandomPos(bin_num_each_table):
    return random.randint(0,bin_num_each_table-1)

def computeCurrentTabSize(currentLevelEleNum, dbSize):
    """
    currentLevelEleNum is the element number before using the hash
    """
    epsilon = 0.75
    bin_num_each_table = math.ceil(currentLevelEleNum/math.pow(math.log2(dbSize),epsilon))
    size_each_bin = math.ceil(2*math.pow(math.log2(dbSize),epsilon))
    return bin_num_each_table,size_each_bin

def padToSize(s, len):
    return str(s).rjust(len, " ")
 
def getRandomStr(strLen):
    str_list = [random.choice(string.digits + string.ascii_letters) for i in range(strLen)]
    return ''.join(str_list)

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
    
def strToDpfKeys(res):
    prgK = strToBytes(res[:16])
    convertK = strToBytes(res[16:32])
    sk = strToBytes(res[32:48])
    CW = []
    for i in range(48, len(res)-1, 18):
        CW.append((strToBytes(res[i:i+16]),int(res[i+16:i+17]),int(res[i+17:i+18])))
    CW.append(int(res[len(res)-1]))
    return prgK, convertK, (sk, CW)

def dpfKeysToStr(dpfK):
    prgK, convertK, (sk, CW) = dpfK
    res = bytesToStr(prgK) + bytesToStr(convertK) + bytesToStr(sk)
    for i in range(1, len(CW)-1):
        s_CW, tL_CW, tR_CW = CW[i]
        res = res + bytesToStr(s_CW)+str(tL_CW)+str(tR_CW)
    res = res + str(CW[len(CW)-1])
    return res

def byteMul01(mul, b0):
    if mul==0:
        return byteXor(b0, b0)
    else:
        return b0

def pirWriteWithEval(Bi, modV, A):
    for i in range(1, len(A)):
        bi = Bi[i]
        A[i] = byteXor(A[i],byteMul01(bi, modV))
                            
def pirWriteWithEvalAndPos(Bi, modV, A, dictKV):
    for i in dict.keys(dictKV):
        bi = Bi[i]
        A[i] = byteXor(A[i],byteMul01(bi, modV))

def readWithPos(Bi, A, dictKV):
    val_0 = (int(0),strXor(str(A[0][1]),str(A[0][1])))
    for i in dict.keys(dictKV):
        bi0 = Bi[i]
        bi1 = strXor(str(A[i][1]),str(A[i][1]))
        if bi0==0:
            bi1=str(A[i][1])
        val_0 = (intXor(val_0[0],bi0*int(A[i][0])),strXor(val_0[1],strXor(bi1,A[i][1])))
    return (str(val_0[0]),str(val_0[1]))

def readData(Bi, A):
    val_0 = (int(0),strXor(str(A[0][1]),str(A[0][1])))
    for i in range(len(A)):
        bi0 = Bi[i]
        bi1 = strXor(str(A[i][1]),str(A[i][1]))
        if bi0==0:
            bi1=str(A[i][1])
        val_0 = (intXor(val_0[0],bi0*int(A[i][0])),strXor(val_0[1],strXor(bi1,A[i][1])))
    return val_0

def dpfGenKeys(index, arrayLength):
    """
    f(alpha, beta)
    we set beta=1
    """
    n = math.ceil(math.log2(arrayLength))
    prgKey = get_random_bytes(16)
    convertKey = get_random_bytes(16)
    L = 0
    R = 1
    s_0List = ["" for i in range(n+1)]
    s_1List = ["" for i in range(n+1)] 
    t_0List = [0 for i in range(n+1)]
    t_1List = [0 for i in range(n+1)]
    s_0List[0] = get_random_bytes(16)
    s_1List[0] = get_random_bytes(16)
    t_0List[0] = 0
    t_1List[0] = 1
    CW = ["" for i in range(n+2)]
    Alpha = bitExtract(index, n)
    for i in range(1, n+1):
        sL_0,tL_0,sR_0,tR_0 = prg(prgKey, s_0List[i-1])
        sL_1,tL_1,sR_1,tR_1 = prg(prgKey, s_1List[i-1])
        Keep = L^Alpha[i]
        Lose = R^Alpha[i]
        s_CW = ""
        if Lose==0:
            s_CW = byteXor(sL_0,sL_1)
        else:
            s_CW = byteXor(sR_0,sR_1)
        tL_CW = tL_0^tL_1^Alpha[i]^1
        tR_CW = tR_0^tR_1^Alpha[i]
        CW[i] = s_CW, tL_CW, tR_CW
        if Keep==0:
            s_0List[i] = byteXor(sL_0,byteMul01(t_0List[i-1],s_CW))
            s_1List[i] = byteXor(sL_1,byteMul01(t_1List[i-1],s_CW))
            t_0List[i] = tL_0^(t_0List[i-1]*tL_CW)
            t_1List[i] = tL_1^(t_1List[i-1]*tL_CW)
        else:
            s_0List[i] = byteXor(sR_0,byteMul01(t_0List[i-1],s_CW))
            s_1List[i] = byteXor(sR_1,byteMul01(t_1List[i-1],s_CW))
            t_0List[i] = tR_0^(t_0List[i-1]*tR_CW)
            t_1List[i] = tR_1^(t_1List[i-1]*tR_CW)
    CW[n+1] = ((-1)**t_1List[n])*(1-convert(convertKey, s_0List[n])+convert(convertKey, s_1List[n]))%2
    k_0 = s_0List[0],CW
    k_1 = s_1List[0],CW
    return prgKey, convertKey, k_0, k_1

def dpfEvalAll(prgKey, convertKey, arrayLength, b, k_b):
    n = math.ceil(math.log2(arrayLength))
    resList = []
    sList = [["" for j in range(2**i)] for i in range(n+1)]
    tList = [[0 for j in range(2**i)] for i in range(n+1)]
    sList[0][0], CW = k_b
    tList[0][0] = b
    for i in range(1, n+1):
        for j in range(0, 2**i, 2):
            tempsL, temptL, tempsR, temptR = prg(prgKey, sList[i-1][j//2])
            sList[i][j] = byteXor(tempsL,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j] = temptL^(tList[i-1][j//2]*CW[i-1][1])
            sList[i][j+1] = byteXor(tempsR,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j+1] = temptR^(tList[i-1][j//2]*CW[i-1][2])
    for i in range(2**n):
        resList.append(((-1)**b)*(convert(convertKey, sList[n][i])+tList[n][i]*CW[n])%2)
    return resList

if __name__=="__main__":

    for lev in range(9,15):
        levTableLength = (int)((1+0.01)*(2**lev))
        T0prfK, T0convertK, T0k_0, T0k_1 = dpfGenKeys(0, levTableLength)
        T1prfK, T1convertK, T1k_0, T1k_1 = dpfGenKeys(0, levTableLength)
        print(len(dpfKeysToStr((T0prfK, T0convertK, T0k_0))))
    #prgKey, convertKey, k_0, k_1 = dpfGenKeys(0,16547)
    #print(len(dpfKeysToStr((prgKey, convertKey, k_0))))
