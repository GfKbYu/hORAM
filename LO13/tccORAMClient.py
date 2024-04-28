import client2 as client
import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from tqdm import tqdm
import tutils
import time
import sys
import pickle

class tORAMClient:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    16-byte Tag, 32-byte value
    """

    def __init__(self, N, BlockSize, access_times) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Initialize the tcp Comm
        """
        self.BlockSize = BlockSize
        self.byteOfComm = 1024
        self.tcpSoc0 = client.tcpClient(client.Addr0,client.Port0,self.byteOfComm)
        self.tcpSoc1 = client.tcpClient(client.Addr1,client.Port1,self.byteOfComm)
        self.tcpSoc0.sendMessage(str(N)+" "+str(self.BlockSize)+" "+str(access_times))
        self.tcpSoc1.sendMessage(str(N)+" "+str(self.BlockSize)+" "+str(access_times))
        self.tcpSocList = [self.tcpSoc0, self.tcpSoc1]

        """
        Initialize the parameters
        """
        self.N = N
        self.lenStash = math.ceil(math.log2(N))
        self.c = 2*self.lenStash
        self.maxLevel = 1 + math.ceil(math.log2(N/(self.c)))
        self.ellCuckoo = min(self.maxLevel, math.ceil(math.log2(math.log2(self.N))))#math.ceil(math.log2(math.pow(math.log2(N), 6)))) # (int)(7*math.log2(math.log2(N)))
        self.countQ = 0 # count access times
        self.countS = 0 # count dummy elements
        self.full = [0 for i in range(self.maxLevel+1)]


        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        self.prfSecretkey = get_random_bytes(16)
        self.prfCipher = AES.new(self.prfSecretkey, AES.MODE_ECB, use_aesni=True)

        self.dummyTag = bytes(8)
        self.dummyK = -2
        self.emptyV = tutils.getDummyStr(self.BlockSize)

        self.availStash = -1

        self.cuckooAlpha = math.ceil(math.log2(self.N))
        self.cuckooEpsilon = 0.01
        self.emptyForm = (bytes(16),-1,self.emptyV)
        
        self.maxLevelCap = (int)((1+self.cuckooEpsilon)*(self.c*2**(self.maxLevel-1)))
        self.eachBucketCapacity = math.ceil(3*math.log2(self.N)/(math.log2(math.log2(self.N))))
        self.threshold_evict = self.cuckooAlpha*math.ceil(math.log2(self.N))

        self.maxLevEpoch = 0

        
        """
        Byte size of each sendMessage
        """
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.PosInTabSize = math.ceil(math.log10(self.maxLevelCap))+1
        self.TagSize = 16

        """
        The overhead
        """
        "Overhead of Oblivious Setup"
        self.bandwidthOfSetup = 0
        self.roundsOfSetup = 0
        self.timeOfSetup = 0
        "Overhead for Access elements"
        self.bandwidthOfAccess = 0
        self.bandwidthOfRebuild = 0
        self.roundsOfAccess = 0
        self.roundsOfRebuild = 0
        self.timeOfAccess = 0
        self.timeOfRebuild = 0
    def packMToStr(self, tagKV):
        return tutils.bytesToStr(tagKV[0])+tutils.padToSize(str(tagKV[1]),self.AddrSize)+str(tagKV[2])

    def unpackStrToM(self, message):
        return tutils.strToBytes(message[:self.TagSize]),int(message[self.TagSize:self.TagSize+self.AddrSize]),str(message[self.TagSize+self.AddrSize:self.TagSize+self.AddrSize+self.BlockSize])

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def prfTag(self, Cipher, level, epoch, key):
        return Cipher.encrypt(self.add_to_16(str(level)+str(epoch)+str(key)))[:16]
    
    def getEpoch(self, level):
        firstRebuild = math.ceil(math.log2(self.N)*(2**(level-2)))
        if level==self.maxLevel:
            return self.maxLevEpoch
        else:
            return (self.countQ-firstRebuild)//(2*firstRebuild)
        
    def resetOverhead(self):
        """
        Reset the overhead parameters
        """
        self.tcpSoc0.Bandwidth,self.tcpSoc1.Bandwidth = 0,0
        self.tcpSoc0.Rounds,self.tcpSoc1.Rounds = 0,0
        self.tcpSoc0.CurrentState,self.tcpSoc1.CurrentState = 'Init','Init'

    def tORAMClientInitialization(self, A): # initialize the array A with the form (k, v)
        """
        Client: generate tag and level hash key. 
        """
        bTime = time.time()
        maxLevelKey = self.prfTag(self.levelMasterCipher,self.maxLevel,0,0)
        self.availStash = 1^(self.maxLevel%2)
        """
        Assume maxLevel is stored in S0, firstly, Send hash key to S1
        """ 
        self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.bytesToStr(maxLevelKey))

        """
        Send data to S1
        """
        for (k,v) in A:
            temp_tag = self.prfTag(self.prfCipher,self.maxLevel,0,k)
            self.tcpSocList[1^(self.maxLevel%2)].sendMessage(self.packMToStr((temp_tag,k,v)))  # send (tag, k, v)
        elementNumInStash = int(self.tcpSocList[1^(self.maxLevel%2)].receiveMessage())

        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV) #self.dummyV+str(self.countS)
                elementNumInStash -= 1
                self.countS += 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV)
                self.countS += 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))

        tempMess0 = self.tcpSocList[(self.maxLevel%2)].receiveMessage()
        tempMess1 = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
        assert tempMess0==tempMess1
        self.full[self.maxLevel]=1
        eTime = time.time()
        """
        Overhead
        """
        self.timeOfSetup += eTime-bTime
        self.bandwidthOfSetup += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfSetup += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        print(self.timeOfSetup)
        self.resetOverhead()

    def tORAMClientAccess(self, op, k, writeV):
        beginMess0 = self.tcpSoc0.receiveMessage()
        beginMess1 = self.tcpSoc1.receiveMessage()
        assert beginMess0==beginMess1=='Done'
        self.resetOverhead()
        bTime = time.time()
        retrievedEle = self.emptyForm
        found = False
        foundInWhichStashAndIndex = [-1,-1]
        stashTempIndex = 0

        tempBand0 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth

        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
                foundInWhichStashAndIndex = [0,stashTempIndex]
            stashTempIndex += 1
        stashTempIndex = 0
        while True: # S1 then
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
                foundInWhichStashAndIndex = [1,stashTempIndex]
            stashTempIndex += 1

        tempBand1 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth


        for lev in range(2,self.ellCuckoo):
            if self.full[lev]==0:
                continue

            tempBand10 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos = tutils.standardHashPosition(levKey,tag,self.c*(2**(lev-1)))
            self.tcpSocList[lev%2].sendMessage(str(pos))

            for _ in range(self.eachBucketCapacity):
                tempTagKV = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
                
                if tempTagKV[1]==k and not found:
                    retrievedEle = tempTagKV
                    found = True
                    sendTagKV = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK,tutils.getRandomStr(self.BlockSize))
                    self.tcpSocList[lev%2].sendMessage(self.packMToStr(sendTagKV))
                else:
                    self.tcpSocList[lev%2].sendMessage(self.packMToStr(tempTagKV))

            
            tempBand11 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            print(lev)
            print(tempBand11-tempBand10)
            print()
        for lev in range(self.ellCuckoo, self.maxLevel+1):
            if self.full[lev]==0:
                continue
            tempBand20 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos0,pos1 = tutils.cuckooHashPosition(levKey,tag,(int)((1+self.cuckooEpsilon)*self.c*(2**(lev-1))))
            self.tcpSocList[lev%2].sendMessage(str(pos0))
            self.tcpSocList[lev%2].sendMessage(str(pos1))

            tempTagKV0 = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
            tempTagKV1 = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

            if tempTagKV0[1]==k and not found:
                retrievedEle = tempTagKV0
                found = True
                sendTagKV0 = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK,tutils.getRandomStr(self.BlockSize))
                self.tcpSocList[lev%2].sendMessage(self.packMToStr(sendTagKV0))
            else:
                self.tcpSocList[lev%2].sendMessage(self.packMToStr(tempTagKV0))
    
            if tempTagKV1[1]==k and not found:
                retrievedEle = tempTagKV1
                found = True
                sendTagKV1 = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK,tutils.getRandomStr(self.BlockSize))
                self.tcpSocList[lev%2].sendMessage(self.packMToStr(sendTagKV1))
            else:
                self.tcpSocList[lev%2].sendMessage(self.packMToStr(tempTagKV1))

            
            tempBand21 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            print(lev)
            print(tempBand21-tempBand20)
            print()

        retrunEle = (retrievedEle[0],retrievedEle[1],retrievedEle[2])
        if op=='w':
            retrievedEle = (retrievedEle[0],retrievedEle[1],writeV)

        stashInd = 0
        

        tempBand2 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth

        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if foundInWhichStashAndIndex[0]==0 and foundInWhichStashAndIndex[1]==stashInd:
                #assert retrunEle==tempTagKV
                self.tcpSoc0.sendMessage(self.packMToStr(retrievedEle))
            else:
                self.tcpSoc0.sendMessage(self.packMToStr(tempTagKV))
            stashInd += 1

        while True: # S1 then
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if foundInWhichStashAndIndex[0]==1 and foundInWhichStashAndIndex[1]==stashInd:
                #assert retrunEle==tempTagKV
                self.tcpSoc1.sendMessage(self.packMToStr(retrievedEle))
            else:
                self.tcpSoc1.sendMessage(self.packMToStr(tempTagKV))
            stashInd += 1

        if foundInWhichStashAndIndex[0]==-1:
            self.tcpSocList[self.availStash].sendMessage(self.packMToStr(retrievedEle))
        else:
            self.tcpSocList[self.availStash].sendMessage(self.packMToStr((self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK,tutils.getRandomStr(self.BlockSize))))
            self.countS += 1
        self.countQ += 1
        
        eTime = time.time()

        tempBand3 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth

        print(tempBand1-tempBand0+tempBand3-tempBand2)

        """
        Overhead of Access
        """
        self.timeOfAccess += eTime-bTime
        self.bandwidthOfAccess += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfAccess += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()
        
        bTime = time.time()

        if self.countQ%self.lenStash==0:
            rebuildL = False
            for i in range(2,self.maxLevel):
                if self.full[i]==0:
                    print('RebuildLev:{}'.format(i))
                    self.tORAMClientRebuild(i)
                    rebuildL = True
                    break
            if not rebuildL:
                print('RebuildLLLev:{}'.format(self.maxLevel))
                self.tORAMClientRebuildL()
        
        eTime = time.time()
        """
        Overhead of Rebuild
        """
        self.timeOfRebuild += eTime-bTime
        self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfRebuild += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()
        
        return retrunEle

    def tORAMClientRebuild(self, rebLev):
        sa = 1^(rebLev%2)
        sb = 1^sa
        tempBand1 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        while True:
            mess = self.tcpSocList[sa].receiveMessage()
            if mess=="Done":
                self.tcpSocList[sb].sendMessage("Done")
                break
            tagKV = self.unpackStrToM(mess)
            self.tcpSocList[sb].sendMessage(self.packMToStr(tagKV))

        
        tempBand2 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        #print(tempBand2-tempBand1)

        rebLevKey = self.prfTag(self.levelMasterCipher,rebLev,self.getEpoch(rebLev),0)
        self.tcpSocList[sa].sendMessage(tutils.bytesToStr(rebLevKey))
        while True:
            mess = self.tcpSocList[sb].receiveMessage()
            if mess=="Done":
                self.tcpSocList[sa].sendMessage("Done")
                break
            tagKV = self.unpackStrToM(mess)
            if tagKV[2]==self.emptyV:
                continue
            sendTagKV = (self.prfTag(self.prfCipher,rebLev,self.getEpoch(rebLev),tagKV[1]), tagKV[1], tagKV[2])
            if tagKV[0][:8]==self.dummyTag:
                sendTagKV = (get_random_bytes(16), tagKV[1], tagKV[2])
            self.tcpSocList[sa].sendMessage(self.packMToStr(sendTagKV))
            
        elementNumInStash = int(self.tcpSocList[sa].receiveMessage())

        
        tempBand3 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        #print(tempBand3-tempBand2)

        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[sa].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV)
                self.countS += 1
                elementNumInStash -= 1
            self.tcpSocList[sb].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))


        tempBand4 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        #print(tempBand4-tempBand3)
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[sa].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV)
                self.countS += 1
            self.tcpSocList[sb].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))
        for i in range(2,rebLev):
            self.full[i]=0
        self.full[rebLev]=1
        self.availStash=sa

        
        tempBand5 = self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        #print(tempBand5-tempBand4)
        
    def tORAMClientRebuildL(self):
        """
        Client: generate tag and level hash key. 
        Assume maxLevel is stored in S0, firstly, Send hash key to S1
        """
        maxLevelKey = self.prfTag(self.levelMasterCipher,self.maxLevel,self.maxLevEpoch+1,0)
        self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.bytesToStr(maxLevelKey))
        
        for i in range(self.N):
            tagKV = self.tORAMClientReadOnly(i)
            sendTagKV = (self.prfTag(self.prfCipher,self.maxLevel,self.maxLevEpoch+1,tagKV[1]),tagKV[1],tagKV[2])
            self.tcpSocList[1^(self.maxLevel%2)].sendMessage(self.packMToStr(sendTagKV))
            
        elementNumInStash = int(self.tcpSocList[1^(self.maxLevel%2)].receiveMessage())
        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV)
                self.countS += 1
                elementNumInStash -= 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))
            
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = self.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyForm:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK,self.emptyV)
                self.countS += 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(self.packMToStr((tmp_tag,tmp_k,tmp_v)))
        for i in range(2,self.maxLevel):
            self.full[i]=0
        self.full[self.maxLevel]=1
        self.availStash = 1^(self.maxLevel%2)
        self.maxLevEpoch += 1

    def tORAMClientReadOnly(self,k):
        retrievedEle = self.emptyForm
        found = False
        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
        while True:
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = self.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
        for lev in range(2,self.ellCuckoo):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos = tutils.standardHashPosition(levKey,tag,self.c*(2**(lev-1)))
            self.tcpSocList[lev%2].sendMessage(str(pos))

            for _ in range(self.eachBucketCapacity):
                tempTagKV = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

                if tempTagKV[1]==k and not found:
                    retrievedEle = tempTagKV
                    found = True
        
        for lev in range(self.ellCuckoo, self.maxLevel+1):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos0,pos1 = tutils.cuckooHashPosition(levKey,tag,(int)((1+self.cuckooEpsilon)*self.c*(2**(lev-1))))
            self.tcpSocList[lev%2].sendMessage(str(pos0))
            self.tcpSocList[lev%2].sendMessage(str(pos1))
            
            tempTagKV0 = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
            tempTagKV1 = self.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

            if tempTagKV0[1]==k and not found:
                retrievedEle = tempTagKV0
                found = True         
            if tempTagKV1[1]==k and not found:
                retrievedEle = tempTagKV1
                found = True
        
        return retrievedEle

if __name__=="__main__":
    random.seed(1)
    BlockSize = 2**5
    NN = 2**14
    A = []
    for i in range(NN):
        A.append((i, tutils.getRandomStr(BlockSize)))
    #print(A)
    access_times = 1#NN#2*NN-1#1#len(A)//2 513#
    coram = tORAMClient(NN,BlockSize,access_times)
    coram.tORAMClientInitialization(A)
    print(coram.maxLevel)
    OP = ["w", "r"]
    error_times = 0
    pbar = tqdm(total=access_times)
    for i in range(access_times):
        index = random.randint(0,len(A)-1)#random.randint(0,1)#random.randint(0,1)#random.randint(0,len(A)-1)
        k = A[index][0]
        v = tutils.getRandomStr(BlockSize)
        op = random.choice(OP)
        retrievedEle = coram.tORAMClientAccess(op, k, v)
        if not (retrievedEle[1], retrievedEle[2])==A[index]:
            error_times += 1
        if op == "w":
            A[index]=(k,v)
        pbar.update(math.ceil((i+1)/(access_times)))

        
    pbar.close()
    print(error_times)
    print(coram.timeOfAccess)
    coram.tcpSoc0.closeConnection()
    coram.tcpSoc1.closeConnection()
    
    data = {'bandwidthOfSetup':coram.bandwidthOfSetup/1024,'roundsOfSetup':coram.roundsOfSetup,'timeOfSetup':coram.timeOfSetup,
            'bandwidthOfAccess':coram.bandwidthOfAccess/(access_times*1024),'roundsOfAccess':coram.roundsOfAccess/(access_times),'timeOfAccess':coram.timeOfAccess/access_times,
            'bandwidthOfRebuild':coram.bandwidthOfRebuild/(access_times*1024),'roundsOfRebuild':coram.roundsOfRebuild/(access_times),'timeOfRebuild':coram.timeOfRebuild/access_times}
    print(data)
    pic = open('/home/zxl/local/hORAM/LO13/Result/LO13_BlockNum{}_Blockize{}.pkl'.format(NN,BlockSize), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()
