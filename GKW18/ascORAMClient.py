import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from tqdm import tqdm
import time
import client
import pickle
import gutils
#from utils import byteXor, strXor, bytesToStr, strToBytes
class aORAMClient:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    """

    def __init__(self, N, BlockSize, access_times) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Initialize the tcp Comm
        """
        self.BlockSize = BlockSize
        self.AddrSize = math.ceil(math.log10(N))+1
        self.PosSize = math.ceil(math.log10(N))+1
        self.byteOfComm = 1024
        self.tcpSoc0 = client.tcpClient(client.Addr0,client.Port0,self.byteOfComm)
        self.tcpSoc1 = client.tcpClient(client.Addr1,client.Port1,self.byteOfComm)
        self.tcpSoc0.sendMessage(str(N)+" "+str(self.BlockSize)+" "+str(access_times))
        self.tcpSoc1.sendMessage(str(N)+" "+str(self.BlockSize)+" "+str(access_times))
        self.tcpSocList = [self.tcpSoc0, self.tcpSoc1]

        """
        Initialize the parameters
        """
        self.emptyForm = (-1,gutils.getRandomStr(self.BlockSize))
        self.N = N
        self.A = 1
        self.Z = 2
        self.ctr = -1
        self.treeDepth = math.ceil(math.log2(self.N)) # 1,2,...,treedepth
        self.leafNum = self.N

        self.masterKey = get_random_bytes(16)
        self.masterCipher = AES.new(self.masterKey, AES.MODE_ECB, use_aesni=True)

        self.localStorage = []

        """
        The overhead
        """
        "Overhead of Oblivious Setup"
        self.bandwidthOfSetup = 0
        self.roundsOfSetup = 0
        self.timeOfSetup = 0
        "Overhead for Access elements"
        self.bandwidthOfAccess = 0
        self.bandwidthOfEviction = 0
        self.roundsOfAccess = 0
        self.roundsOfEviction = 0
        self.timeOfAccess = 0
        self.timeOfEviction = 0

        self.clientAcessStorage = 0

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def prfTag(self, Cipher, key):
        return Cipher.encrypt(self.add_to_16(str(key)))[:16]
    
    def hashPosition(self, tag):
        """
        Ensure the position 0 does not store elements
        """
        secretkey0 = self.masterCipher.encrypt(self.add_to_16(str(0)))
        return hash(str(tag)+str(secretkey0)) % self.leafNum
    
    def packKVPosToStr(self,k,v,leafPos):
        return gutils.padToSize(str(k),self.AddrSize)+str(v)+gutils.padToSize(str(leafPos),self.PosSize)
    
    def unpackStrToKV(self,mess):
        return (int(mess[:self.AddrSize]),str(mess[self.AddrSize:]))
    
    def packKVToStr(self,k,v):
        return gutils.padToSize(str(k),self.AddrSize)+str(v)
    
    def resetOverhead(self):
        """
        Reset the overhead parameters
        """
        self.tcpSoc0.Bandwidth,self.tcpSoc1.Bandwidth = 0,0
        self.tcpSoc0.Rounds,self.tcpSoc1.Rounds = 0,0
        self.tcpSoc0.CurrentState,self.tcpSoc1.CurrentState = 'Init','Init'

    def aORAMClientInitialization(self, arrayA):
        self.resetOverhead()
        bTime = time.time()
        for (k,v) in arrayA:
            leafPos = self.hashPosition(self.prfTag(self.masterCipher,k))
            self.tcpSoc0.sendMessage(self.packKVPosToStr(k,v,leafPos))
            self.tcpSoc1.sendMessage(self.packKVPosToStr(k,v,leafPos))

        while True:
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            self.localStorage.append(self.unpackStrToKV(mess))
        eTime = time.time()
        """
        Overhead
        """
        self.timeOfSetup += eTime-bTime
        self.bandwidthOfSetup += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfSetup += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()

    def aORAMClientAccess(self, op, queryK, writeV):
        beginMess0 = self.tcpSoc0.receiveMessage()
        beginMess1 = self.tcpSoc1.receiveMessage()
        assert beginMess0==beginMess1=='Done'
        self.resetOverhead()
        bTime = time.time()
        found = False
        retrievedEle = (-1,gutils.getRandomStr)
        for i in range(len(self.localStorage)):
            if self.localStorage[i][0]==queryK and not found:
                retrievedEle=self.localStorage[i]
                found = True
                break
        if found:
            self.localStorage.remove(retrievedEle)

        leafPos = self.hashPosition(self.prfTag(self.masterCipher,queryK))
        pk,ck,k0,k1 = gutils.dpfGenKeys(leafPos, self.leafNum)

        self.tcpSoc0.sendMessage(gutils.dpfKeysToStr((pk,ck,k0)))
        self.tcpSoc1.sendMessage(gutils.dpfKeysToStr((pk,ck,k1)))

        for _ in range(self.treeDepth):
            for _ in range(self.Z):
                (accessK0,accessV0) = self.unpackStrToKV(self.tcpSoc0.receiveMessage())
                (accessK1,accessV1) = self.unpackStrToKV(self.tcpSoc1.receiveMessage())
                (recK, recV) = (gutils.intXor(accessK0,accessK1),gutils.strXor(accessV0,accessV1))
                if recK==queryK and not found:
                    retrievedEle=(recK, recV)
                    found = True

        returnEle = (retrievedEle[0],retrievedEle[1])
        if op=='w':
            retrievedEle = (retrievedEle[0],writeV)
        self.localStorage.append(retrievedEle)
        self.ctr = (self.ctr+1)%self.leafNum
        eTime = time.time()
        """
        Overhead
        """
        self.timeOfAccess += eTime-bTime
        self.bandwidthOfAccess += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfAccess += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()

        bTime = time.time()
        if self.ctr%self.A==0:
            self.aORAMClientEvict()
        self.clientPermStorage = len(self.localStorage)
        eTime = time.time()
        """
        Overhead
        """
        self.timeOfEviction += eTime-bTime
        self.bandwidthOfEviction += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfEviction += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()

        return returnEle

    def aORAMClientEvict(self):
        leafPos = gutils.reverseBit(self.ctr,self.treeDepth)
        for i in range(1,self.treeDepth+1):
            for j in range(self.Z):
                recKV = self.unpackStrToKV(self.tcpSoc0.receiveMessage())
                if recKV!=self.emptyForm and not gutils.whetherKVInStash(recKV,self.localStorage):
                    self.localStorage.append(recKV)
        
        random.shuffle(self.localStorage)
        tempPos = []
        for (k,_) in self.localStorage:
            loc = self.hashPosition(self.prfTag(self.masterCipher,k))
            tempPos.append(loc)

        tempBuildPath = [[self.emptyForm for _ in range(self.Z)] for _ in range(self.treeDepth)]

        haveWriteDict = {}
        for i in range(len(self.localStorage)):
            kV = self.localStorage[i]
            tmpLev = gutils.findSharedLevel(tempPos[i],leafPos,self.treeDepth)
            for wLev in range(tmpLev-1,-1,-1):
                if self.emptyForm in tempBuildPath[wLev]:
                    tmpInd = tempBuildPath[wLev].index(self.emptyForm)
                    tempBuildPath[wLev][tmpInd] = kV
                    haveWriteDict[kV[0]]=kV[1]
                    break

        for kVList in tempBuildPath:
            for kV in kVList:
                self.tcpSoc0.sendMessage(self.packKVToStr(kV[0],kV[1]))
                self.tcpSoc1.sendMessage(self.packKVToStr(kV[0],kV[1]))

        for k in haveWriteDict.keys():        
            self.localStorage.remove((k,haveWriteDict[k]))
        
        self.clientAcessStorage = len(self.localStorage)+self.Z*self.treeDepth

if __name__=="__main__":
    NN = 2**10
    BlockSize = 2**5
    A = []
    for i in range(NN):
        A.append((i, gutils.getRandomStr(BlockSize))) 
    
    access_times = 2*NN-1
    coram = aORAMClient(NN,BlockSize,access_times)
    coram.aORAMClientInitialization(A)
    
    OP = ["w", "r"]
    error_times = 0
    pbar = tqdm(total=access_times)

    for i in range(access_times):
        index = random.randint(0,len(A)-1)
        k = A[index][0]
        v = gutils.getRandomStr(BlockSize)
        op = random.choice(OP)
        retrievedEle = coram.aORAMClientAccess(op, k, v)
        if not (retrievedEle[0], retrievedEle[1])==A[index]:
            error_times += 1
        if op == "w":
            A[index]=(k,v)
        pbar.update(math.ceil((i+1)/(access_times)))
    pbar.close()

    coram.tcpSoc0.closeConnection()
    coram.tcpSoc1.closeConnection()

    data = {'clientAcessStorage':coram.clientAcessStorage,'bandwidthOfSetup':coram.bandwidthOfSetup/1024,'roundsOfSetup':coram.roundsOfSetup,'timeOfSetup':coram.timeOfSetup,
            'bandwidthOfAccess':coram.bandwidthOfAccess/(access_times*1024),'roundsOfAccess':coram.roundsOfAccess/(access_times),'timeOfAccess':coram.timeOfAccess/access_times,
            'bandwidthOfEviction':coram.bandwidthOfEviction/(access_times*1024),'roundsOfEviction':coram.roundsOfEviction/(access_times),'timeOfEviction':coram.timeOfEviction/access_times}
    pic = open('/home/zxl/local/hORAM/GKW18/Result/GKW18_BlockNum{}_Blockize{}.pkl'.format(NN,BlockSize), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()





            


