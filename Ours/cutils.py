import math
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import time
import numpy as np
import random
import string
import multiprocessing
from functools import partial
import time
from multiprocessing import Pool

def padToSize(s, len):
    return str(s).rjust(len, " ")

def getRandomStr(strLen):
    str_list = [random.choice(string.digits+string.ascii_letters) for i in range(strLen)]
    return ''.join(str_list)

def add_to_16(value):
    while len(value) % 16 != 0:
        value += "\0"
    return str.encode(value) 

def convert(convertCipher, s):
    return int.from_bytes(convertCipher.encrypt(add_to_16(str(s)))[:16], 'big', signed=False)%2

def prg2(secretKey, s):
    """
    lambda -> 2*lambda +2 
    Assume s is 16-byte
    """
    secretCipher = AES.new(secretKey, AES.MODE_ECB, use_aesni=True)
    sL = secretCipher.encrypt(add_to_16(str(0)+str(s)))[:16]
    sR = secretCipher.encrypt(add_to_16(str(1)+str(s)))[:16]
    #sha1 = hashlib.sha1()
    #sha1.update(add_to_16(str(2)+str(secretKey)+str(s)))
    tL = int.from_bytes(sL, 'big', signed=False)%2
    #sha1 = hashlib.sha1()
    #sha1.update(add_to_16(str(3)+str(secretKey)+str(s)))
    tR = int.from_bytes(sR, 'big', signed=False)%2
    return sL,tL,sR,tR

def prg(secretCipher, s):
    """
    lambda -> 2*lambda +2 
    Assume s is 16-byte
    """
    #secretCipher = AES.new(secretKey, AES.MODE_ECB, use_aesni=True)
    sL = secretCipher.encrypt(add_to_16(str(0)+str(s)))[:16]
    sR = secretCipher.encrypt(add_to_16(str(1)+str(s)))[:16]
    #sha1 = hashlib.sha1()
    #sha1.update(add_to_16(str(2)+str(secretKey)+str(s)))
    tL = int.from_bytes(sL, 'big', signed=False)%2
    #sha1 = hashlib.sha1()
    #sha1.update(add_to_16(str(3)+str(secretKey)+str(s)))
    tR = int.from_bytes(sR, 'big', signed=False)%2
    return sL,tL,sR,tR

def bitExtract(ind, n):
    res = [0 for i in range(n+1)]
    for i in range(n):
        res[i+1] = ind>>(n-i-1)&1
    return res

def intXor(s1, s2):
    return int(s1)^int(s2)

def byteXor(b1,b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def strXor(s: str, k: str):
    return byteXor(s.encode(),k.encode()).decode()
    #return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s, k))

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
    val_0 = (int(0)," "*len(A[0][1]))
    for i in dict.keys(dictKV):
        if Bi[i]==1:
            val_0 = (intXor(val_0[0],int(A[i][0])),strXor(val_0[1],A[i][1]))
    return (str(val_0[0]),str(val_0[1]))

def xorTwoIntAndStrings(ele0,ele1):
    return (intXor(int(ele0[0]),int(ele1[0])),strXor(str(ele0[1]),str(ele1[1])))

import concurrent.futures

def readWithPosParallel(tempL):
    if len(tempL) == 1:
        return tempL[0]
    elif len(tempL) == 2:
        return xorTwoIntAndStrings(tempL[0],tempL[1])
    else:
        mid = len(tempL) // 2
        with concurrent.futures.ThreadPoolExecutor() as executor:
            left_result = executor.submit(readWithPosParallel, tempL[:mid])
            right_result = executor.submit(readWithPosParallel, tempL[mid:])
            #pool.close()
            #pool.join()
            return xorTwoIntAndStrings(left_result.result(), right_result.result())
        
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
    prgCipher = AES.new(prgKey, AES.MODE_ECB, use_aesni=True)
    convertCipher = AES.new(convertKey, AES.MODE_ECB, use_aesni=True)

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
        sL_0,tL_0,sR_0,tR_0 = prg(prgCipher, s_0List[i-1])
        sL_1,tL_1,sR_1,tR_1 = prg(prgCipher, s_1List[i-1])
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
    CW[n+1] = ((-1)**t_1List[n])*(1-convert(convertCipher, s_0List[n])+convert(convertCipher, s_1List[n]))%2
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
    prgCipher = AES.new(prgKey, AES.MODE_ECB, use_aesni=True)
    convertCipher = AES.new(convertKey, AES.MODE_ECB, use_aesni=True)
    for i in range(1, n+1):
        for j in range(0, 2**i, 2):
            tempsL, temptL, tempsR, temptR = prg(prgCipher, sList[i-1][j//2])
            sList[i][j] = byteXor(tempsL,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j] = temptL^(tList[i-1][j//2]*CW[i-1][1])
            sList[i][j+1] = byteXor(tempsR,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j+1] = temptR^(tList[i-1][j//2]*CW[i-1][2])
    for i in range(2**n):
        resList.append(((-1)**b)*(convert(convertCipher, sList[n][i])+tList[n][i]*CW[n])%2)
    return resList

def computeDPFEval(prgKey, cwI1, sTIJ):
    tempsL, temptL, tempsR, temptR = prg2(prgKey, sTIJ[0])
    sij = byteXor(tempsL,byteMul01(sTIJ[1],cwI1[0]))
    tij = temptL^(sTIJ[1]*cwI1[1])
    sij1 = byteXor(tempsR,byteMul01(sTIJ[1],cwI1[0]))
    tij1 = temptR^(sTIJ[1]*cwI1[2])
    return 1+sTIJ[2],2*sTIJ[3],sij,tij,sij1,tij1

def dpfEvalAllParallel(prgKey, convertKey, arrayLength, b, k_b):
    convertCipher = AES.new(convertKey, AES.MODE_ECB, use_aesni=True)
    n = math.ceil(math.log2(arrayLength))
    resList = []
    sAndTList = [[("",0,i,j) for j in range(2**i)] for i in range(n+1)]
    CW = k_b[1]
    sAndTList[0][0] = k_b[0],b,0,0
    pool = multiprocessing.Pool()
    for i in range(1, n+1):
        partial_function = partial(computeDPFEval,prgKey,CW[i-1])
        results = pool.map(partial_function, sAndTList[i-1])
        for res in results:
            sAndTList[res[0]][res[1]]=(res[2],res[3],res[0],res[1])
            sAndTList[res[0]][res[1]+1]=(res[4],res[5],res[0],res[1]+1)
    pool.close()
    for i in range(2**n):
        resList.append(((-1)**b)*(convert(convertCipher, sAndTList[n][i][0])+sAndTList[n][i][1]*CW[n])%2)
    return resList

# 自定义函数来计算两个字符串的异或
def xor_strings(str1, str2):
    print(str1,str2)
    result = strXor(str1,str2)
    print(result)
    return result

# 自定义函数来对一组字符串进行异或求和
def xor_sum(strings):
    if len(strings) == 1:
        return strings[0]
    elif len(strings) == 2:
        return xor_strings(strings[0], strings[1])
    else:
        mid = len(strings) // 2
        with Pool() as pool:
            left_result = pool.apply_async(xor_sum, (strings[:mid],))
            right_result = pool.apply_async(xor_sum, (strings[mid:],))
            return xor_strings(left_result.get(), right_result.get())

if __name__ == '__main__':

    pk = "123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123123"

    random.seed(1)
    #print(strXor("helldddfso","worddddld"))
    # 定义要处理的字符串数组
    str_array = [getRandomStr(5),getRandomStr(5),getRandomStr(5),getRandomStr(5)]
    print(str_array)
    # 使用xor_sum函数并行地对字符串数组中的每一对字符串求和
    total_sum = xor_sum(str_array)

    # 打印结果
    print("XOR sum:", total_sum)


    plp = getRandomStr(5)
    plp2 = getRandomStr(5)
    BT = time.time()
    resl = strXor(strXor(strXor(str_array[0],str_array[1]),str_array[2]),str_array[3])
    print(resl)
    ET = time.time()
    BT2 = time.time()
    resl = byteXor(plp.encode(),plp2.encode()).decode()
    ET2 = time.time()
    print(ET-BT)
    print(ET2-BT2)
    N = 2**20
    dictKV = {}
    for i in range(N):
        dictKV[i]=i
    A = []
    for i in range(N):
        A.append((i,getRandomStr(32)))
    print(A[0])
    bTM = time.time()
    prfK, convertK, k_0, k_1 = dpfGenKeys(0, N)
    mess0 = dpfKeysToStr((prfK, convertK, k_0))
    mess1 = dpfKeysToStr((prfK, convertK, k_1))
    prgK0, convertK0, k_00 = strToDpfKeys(mess0)
    prgK1, convertK1, k_01 = strToDpfKeys(mess1)
    bLT = time.time()
    Bi0 = dpfEvalAll(prgK0,convertK0,N,0,k_00)
    eLT = time.time()
    print(eLT-bLT)
    Bi1 = dpfEvalAllParallel(prgK1,convertK1,N,1,k_01)
    print(time.time()-eLT)
    eTM = time.time()

    eTT = time.time()
    val1 = readWithPos(Bi1,A,dictKV)
    eTT2 = time.time()
    print(eTT2-eTT)
    val0 = readWithPos(Bi0,A,dictKV)
    print(time.time()-eTM)
    resR0 = intXor(val0[0],val1[0]),strXor(val0[1],val1[1])
    print(resR0)


    b1 = get_random_bytes(16)
    b2 = get_random_bytes(16)
    bT1 = time.time()
    byteXor(b1,b2)
    bT2 = time.time()
    strXor(getRandomStr(1024),getRandomStr(1024))
    bT3 = time.time()
    print(bT3-bT2,bT2-bT1)
    """
    
    #partial_function = partial(paralEvalAll,sL)
    
    #pool_obj = Pool()
    #pool_obj.map(partial_function, [0,1,2])
    #p=multiprocessing.Process(target=paralEvalAll,args=(sL,range(0,3)))
    #p.start() 
    #p.join()
    print(sL[:])

    #pool_obj.map(partial_function, range(0, 3))
    print(sL)

    dictKV = {}
    for i in range(2**15):
        dictKV[i]=i
    A = []
    for i in range(33095):
        A.append((i,getRandomStr(32)))
    print(A[0])
    bTM = time.time()
    prfK, convertK, k_0, k_1 = dpfGenKeys(0, 33095)
    mess0 = dpfKeysToStr((prfK, convertK, k_0))
    mess1 = dpfKeysToStr((prfK, convertK, k_1))
    prgK0, convertK0, k_00 = strToDpfKeys(mess0)
    prgK1, convertK1, k_01 = strToDpfKeys(mess1)
    eTM = time.time()
    print(eTM-bTM)
    print()
    Bi0 = dpfEvalAll(prgK0,convertK0,33095,0,k_00)
    Bi1 = dpfEvalAll(prgK1,convertK1,33095,1,k_01)
    val0 = readWithPos(Bi0,A,dictKV)
    val1 = readWithPos(Bi1,A,dictKV)
    resR0 = intXor(val0[0],val1[0]),strXor(val0[1],val1[1])
    print(resR0)

    """
    