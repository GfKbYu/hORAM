import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import sys
from tqdm import tqdm
import time
import client
import cutils
import pickle

"""
tcp: 粘包
udp: 无序+丢包
"""

class ORAMClient:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    16-byte tag and 32-byte block
    """
    def __init__(self, N, BlockSize, access_times) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Store in client
        """
        self.N = N
        self.access_times = access_times
        self.BlockSize = BlockSize # real data block size
        self.L = math.ceil(math.log2(N))
        self.ell = min(self.L-1, math.ceil(2*math.log2(math.log2(N)))) # N: 16, 64, 64*4
        self.ecEllLength = 2**(self.ell+1)+math.ceil(math.log2(N))*(self.L-self.ell)
        self.ctr = 0
        self.full = [0 for i in range(self.L-self.ell+1)] # 1,2,...
        self.eleEmptyForm = (-1,cutils.getRandomStr(self.BlockSize))
        self.tagEmptyForm = bytes(16)
        tmp_val = 0
        self.dummyT = tmp_val.to_bytes(16,'big') # dummy tag
        self.dummyE = -2 # str(sys.maxsize) # dummy addr
        self.ellEpoch = 0
        self.Lepoch = 0
        self.ellAccessTimes = 0

        """
        To generate the level key
        """
        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        """
        To generate the tag
        """
        self.prfSecretkey = get_random_bytes(16)
        self.prfCipher = AES.new(self.prfSecretkey, AES.MODE_ECB, use_aesni=True)

        self.cuckooAlpha = math.ceil(math.log2(N))
        self.cuckooEpsilon = 0.01        
        self.ellTableLength = (int)((1+self.cuckooEpsilon)*self.ecEllLength)
        self.LTableLength = (int)((1+self.cuckooEpsilon)*(2**self.L))
        self.byteOfCom = 1024
        
        """
        Other parameters
        """
        self.lenEBAndTB = 0
        self.lenES = 0
        self.tcpSoc0 = client.tcpClient(client.Addr0, client.Port0, self.byteOfCom)
        self.tcpSoc1 = client.tcpClient(client.Addr1, client.Port1, self.byteOfCom)
        self.tcpSoc0.sendMessage(str(self.N)+" "+str(self.BlockSize)+" "+str(self.access_times))
        self.tcpSoc1.sendMessage(str(self.N)+" "+str(self.BlockSize)+" "+str(self.access_times))

        """
        Byte size of each sendMessage
        """
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.PosInTabSize = math.ceil(math.log10(self.LTableLength))+1
        self.TagSize = 16
        self.BSSize = 2
        self.FullFlagSize = 1

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

        self.clientAcessStorage = 0

    def getDPFKeySize(self, tableLen): 
        return 49+18*math.ceil(math.log2(tableLen))

    def padToSize(s, len):
        return str(s).rjust(len, " ")
 
    def resetOverhead(self):
        """
        Reset the overhead parameters
        """
        self.tcpSoc0.Bandwidth,self.tcpSoc1.Bandwidth = 0,0
        self.tcpSoc0.Rounds,self.tcpSoc1.Rounds = 0,0
        self.tcpSoc0.CurrentState,self.tcpSoc1.CurrentState = 'Init','Init'

    def receiveM(self, soc):
        return soc.receiveMessage()
            
    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def generateTag(self, key):
        return self.prfCipher.encrypt(self.add_to_16(str(key)))[:16]

    def generateLevelCipher(self, level, epoch):
        tmpKey = self.levelMasterCipher.encrypt(self.add_to_16(str(level)+str(epoch)))
        return  AES.new(tmpKey, AES.MODE_ECB, use_aesni=True)
    
    def getEpoch(self, level):
        if level==self.ell:
            return self.ellEpoch#(self.ctr)//(2*(2**level)) + self.ctr//math.ceil(math.log2(self.N))
        elif level==self.L:
            return self.Lepoch#self.ctr//(2**level)
        else:
            #assert self.ctr>=2**level
            return max(0, (self.ctr-2**level))//(2*(2**level))
    
    def secretShareTag(self, tag):
        tag_0 = get_random_bytes(16)
        tag_1 = cutils.byteXor(tag, tag_0)
        return tag_0, tag_1
    
    def secretShareLevel(self, levelStr):
        level_0 = str(random.randint(0,sys.maxsize))
        level_1 = cutils.strXor(levelStr, level_0)
        return level_0, level_1

    def hashPosition(self, levelCipher, tag, tableLength):
        """
        Ensure the position 0 does not store elements
        """
        secretkey0 = levelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = levelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        return hash(str(secretkey0)+str(tag)) % (tableLength-1) + 1, hash(str(secretkey1)+str(tag)) % (tableLength-1) + 1

    def oramClientInitialization(self, A):
        self.resetOverhead()
        bTime = time.time()
        LLevelCipher = self.generateLevelCipher(self.L, 0)
        ellLevelCipher = self.generateLevelCipher(self.ell, 0)
        for (virAddr,realVal) in A: # (int, str)
            tag = self.generateTag(virAddr)
            shareTag0, shareTag1 = self.secretShareTag(tag)
            posNowLevel0,posNowLevel1 = self.hashPosition(LLevelCipher, tag, self.LTableLength)
            posEllLevel0,posEllLevel1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)


            dataMessage0 = cutils.padToSize(str(virAddr),self.AddrSize)+str(realVal)+cutils.bytesToStr(shareTag0)+cutils.padToSize(str(posNowLevel0),self.PosInTabSize)+cutils.padToSize(str(posNowLevel1),self.PosInTabSize)+cutils.padToSize(str(posEllLevel0),self.PosInTabSize)+cutils.padToSize(str(posEllLevel1),self.PosInTabSize)            
            dataMessage1 = cutils.padToSize(str(virAddr),self.AddrSize)+str(realVal)+cutils.bytesToStr(shareTag1)+cutils.padToSize(str(posNowLevel0),self.PosInTabSize)+cutils.padToSize(str(posNowLevel1),self.PosInTabSize)+cutils.padToSize(str(posEllLevel0),self.PosInTabSize)+cutils.padToSize(str(posEllLevel1),self.PosInTabSize)
            
            """
            send to server
            """
            self.tcpSoc0.sendMessage(dataMessage0)
            self.tcpSoc1.sendMessage(dataMessage1)

        tmpData = self.receiveM(self.tcpSoc0)
        self.lenES = int(tmpData[:self.BSSize])
        self.lenEBAndTB = int(tmpData[self.BSSize:2*self.BSSize])
        self.full[0] = int(tmpData[2*self.BSSize:])
        self.full[self.L-self.ell]=1

        eTime = time.time()
        """
        Overhead
        """
        self.timeOfSetup += eTime-bTime
        self.bandwidthOfSetup += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfSetup += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()


    def oramClientAccess(self, op, a, writeV):
        beginMess0 = self.tcpSoc0.receiveMessage()
        beginMess1 = self.tcpSoc1.receiveMessage()
        assert beginMess0==beginMess1=='Done'
        self.resetOverhead()
        bTime = time.time()
        found = False
        tag = self.generateTag(a)
        retrievedEle = (-1,cutils.getRandomStr(self.BlockSize))                    
        writeModTag = (cutils.byteXor(tag, self.dummyT))
            
        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)

            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, self.ellTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, self.ellTableLength)
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue

            levTableLength = (int)((1+self.cuckooEpsilon)*(1<<lev))
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)
            
            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, levTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, levTableLength)
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))

        posList = []
        """
        Receive block
        """
        if self.lenEBAndTB>1:
            tempBPos = 0
            for i in range(self.lenEBAndTB-1, 0, -1):
                tempMess = self.receiveM(self.tcpSoc0)
                recK = int(tempMess[:self.AddrSize])
                recV = str(tempMess[self.AddrSize:])
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    tempBPos = i
                    found = True
            posList.append(tempBPos)

        if self.lenES>1:
            tempEPos = 0
            for i in range(1, self.lenES):
                tempMess = self.receiveM(self.tcpSoc0)
                recK = int(tempMess[:self.AddrSize])
                recV = str(tempMess[self.AddrSize:])
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    tempEPos = i
                    found = True
            posList.append(tempEPos)

        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)
            
            temp_share_data_0 = self.receiveM(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveM(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveM(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveM(self.tcpSoc1)# temp_d11.split( )
            
            temp_data_0 = (cutils.intXor(int(temp_share_data_0[:self.AddrSize]),int(temp_share_data_01[:self.AddrSize])),cutils.strXor(temp_share_data_0[self.AddrSize:],temp_share_data_01[self.AddrSize:]))
            temp_data_1 = (cutils.intXor(int(temp_share_data_1[:self.AddrSize]),int(temp_share_data_11[:self.AddrSize])),cutils.strXor(temp_share_data_1[self.AddrSize:],temp_share_data_11[self.AddrSize:]))
            tempEllPos0 = 0
            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_0
                found = True
                tempEllPos0 = pos_0
            posList.append(tempEllPos0)
            tempEllPos1 = 0
            if (not found) and temp_data_1[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_1
                found = True
                tempEllPos1 = pos_1
            posList.append(tempEllPos1)

        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)#ET0[lev-self.ell].getPos(levelCipher, tag)
        
            temp_share_data_0 = self.receiveM(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveM(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveM(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveM(self.tcpSoc1)# temp_d11.split( )
            
            temp_data_0 = (cutils.intXor(int(temp_share_data_0[:self.AddrSize]),int(temp_share_data_01[:self.AddrSize])),cutils.strXor(temp_share_data_0[self.AddrSize:],temp_share_data_01[self.AddrSize:]))
            temp_data_1 = (cutils.intXor(int(temp_share_data_1[:self.AddrSize]),int(temp_share_data_11[:self.AddrSize])),cutils.strXor(temp_share_data_1[self.AddrSize:],temp_share_data_11[self.AddrSize:]))
            tempLevPos0 = 0
            if (not found) and temp_data_0[0]==a:
                retrievedEle = temp_data_0
                found = True
                tempLevPos0 = pos_0
            posList.append(tempLevPos0)
            tempLevPos1 = 0
            if (not found) and temp_data_1[0]==a:
                retrievedEle = temp_data_1
                found = True
                tempLevPos1 = pos_1
            posList.append(tempLevPos1)

    
        """
        Send modified KV
        """
        posLIndex = 0

        if self.lenEBAndTB>1:
            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], self.lenEBAndTB)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1

        if self.lenES>1:
            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], self.lenES)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1      
            
        if self.full[0]==1:
            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], self.ellTableLength)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1

            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], self.ellTableLength)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1
        
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))

            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], levTableLength)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1

            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(posList[posLIndex], levTableLength)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.bytesToStr(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            posLIndex += 1
        
        returnEle = (retrievedEle[0], retrievedEle[1])
        retrievedEle = (retrievedEle[0], retrievedEle[1])
        if op == "w":
            retrievedEle = (retrievedEle[0], writeV)

        tag_0 = get_random_bytes(16)
        tag_1 = cutils.byteXor(tag, tag_0)

        self.tcpSoc0.sendMessage(cutils.padToSize(str(retrievedEle[0]),self.AddrSize)+str(retrievedEle[1])+cutils.bytesToStr(tag_0))
        self.tcpSoc1.sendMessage(cutils.padToSize(str(retrievedEle[0]),self.AddrSize)+str(retrievedEle[1])+cutils.bytesToStr(tag_1))


        self.ctr += 1
        self.ellAccessTimes += 1
        self.lenEBAndTB += 1

        eTime = time.time()
        
        """
        Overhead
        """
        self.timeOfAccess += eTime-bTime
        self.bandwidthOfAccess += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfAccess += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()
        
        bTime = time.time()
        if self.ctr%(2**self.L)==0:
            self.oramClientRebuildL()
            eTime = time.time()
            """
            Overhead
            """
            self.timeOfRebuild += eTime-bTime
            self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            self.roundsOfRebuild += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        elif self.ctr%(2**(self.ell+1)) == 0:
            for j in range(self.ell+1, self.L):
                if self.full[j-self.ell]==0:
                    self.oramClientRebuild(j)
                    eTime = time.time()
                    self.full[j-self.ell]=1
                    """
                    Overhead
                    """
                    self.timeOfRebuild += eTime-bTime
                    self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
                    self.roundsOfRebuild += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
                    break

        elif self.ellAccessTimes % math.ceil(math.log2(self.N)) == 0:
            self.oramClientRebuildFL()
            eTime = time.time()
            """
            Overhead
            """
            self.timeOfRebuild += eTime-bTime
            self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
            self.roundsOfRebuild += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        
        self.resetOverhead()

        return returnEle
    
    def oramClientRebuildFL(self):
        self.ellEpoch += 1
        newEllLevCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        self.clientAcessStorage = max(self.L+2,self.clientAcessStorage)
        tempD = []
        while True:
            tes = self.receiveM(self.tcpSoc0)
            if tes == "Done":
                for mess in tempD:
                    """
                    send to server
                    """
                    self.tcpSoc0.sendMessage(mess)
                    self.tcpSoc1.sendMessage(mess)
                self.lenES=int(self.receiveM(self.tcpSoc0))
                self.lenEBAndTB=1
                self.full[0]=1
                break
            recTagStr0 = self.receiveM(self.tcpSoc0)
            recTagStr1 = self.receiveM(self.tcpSoc1)
            (recK,recV) = int(tes[:self.AddrSize]),str(tes[self.AddrSize:self.AddrSize+self.BlockSize])
            tmpTag0 = cutils.strToBytes(recTagStr0)
            tmpTag1 = cutils.strToBytes(recTagStr1)
            tag = cutils.byteXor(tmpTag0,tmpTag1)

            posEllLevel0 = random.randint(1,self.ellTableLength-1)
            posEllLevel1 = random.randint(1,self.ellTableLength-1)
            if tag==self.dummyT:
                (recK,recV) = (self.dummyE,cutils.getRandomStr(self.BlockSize))
            else:             
                (posEllLevel0,posEllLevel1) = self.hashPosition(newEllLevCipher, tag, self.ellTableLength)

            tempD.append(cutils.padToSize(str(recK),self.AddrSize)+str(recV)+cutils.padToSize(str(posEllLevel0),self.PosInTabSize)+cutils.padToSize(str(posEllLevel1),self.PosInTabSize))
            if len(tempD)==self.L:
                for mess in tempD:
                    """
                    send to server
                    """
                    self.tcpSoc0.sendMessage(mess)
                    self.tcpSoc1.sendMessage(mess)
                tempD = []   

        self.full[0] = 1
        self.ellAccessTimes = 0

    def oramClientRebuild(self, lev):
        self.ellEpoch += 1
        newLevCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
        newEllCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        self.clientAcessStorage = max(self.L+2,self.clientAcessStorage)
        tempD = []
        while True:
            tes =  self.receiveM(self.tcpSoc0)#recEleStr.split( )
            if tes == "Done":
                for mess in tempD:
                    """
                    send to server
                    """
                    self.tcpSoc0.sendMessage(mess)
                    self.tcpSoc1.sendMessage(mess)
                lenFull = self.receiveM(self.tcpSoc0).split( )
                self.lenES=int(lenFull[0])
                self.lenEBAndTB=1
                self.full[0]=int(lenFull[1])
                break
            recTagStr0 = self.receiveM(self.tcpSoc0)#self.tcpSoc0.receiveMessage()   
            recTagStr1 = self.receiveM(self.tcpSoc1)#self.tcpSoc1.receiveMessage()

            (recK,recV) = int(tes[:self.AddrSize]),str(tes[self.AddrSize:self.AddrSize+self.BlockSize])
            tmpTag0 = cutils.strToBytes(recTagStr0)
            tmpTag1 = cutils.strToBytes(recTagStr1)
            tag = cutils.byteXor(tmpTag0,tmpTag1)

            tempTabLen = (int)((1+self.cuckooEpsilon)*(2**lev))
            posLev0 = random.randint(1,tempTabLen-1)
            posLev0 = random.randint(1,tempTabLen-1)
            posEll0 = random.randint(1,self.ellTableLength-1)
            posEll1 = random.randint(1,self.ellTableLength-1)

            if tag==self.dummyT:
                (recK,recV) = (self.dummyE,cutils.getRandomStr(self.BlockSize))
            else:                  
                (posLev0,posLev1) = self.hashPosition(newLevCipher,tag, tempTabLen)
                (posEll0,posEll1) = self.hashPosition(newEllCipher, tag, self.ellTableLength)

            tempD.append(cutils.padToSize(str(recK),self.AddrSize)+str(recV)+cutils.padToSize(str(posLev0),self.PosInTabSize)+cutils.padToSize(str(posLev1),self.PosInTabSize)+cutils.padToSize(str(posEll0),self.PosInTabSize)+cutils.padToSize(str(posEll1),self.PosInTabSize))
            if len(tempD)==self.L:
                for mess in tempD:
                    """
                    send to server
                    """
                    self.tcpSoc0.sendMessage(mess)
                    self.tcpSoc1.sendMessage(mess)
                tempD = []
        for j in range(self.ell+1,lev):
            self.full[j-self.ell]=0
        self.full[lev-self.ell] = 1
        self.ellAccessTimes = 0

    def oramClientRebuildL(self):
        newLLevelCipher = self.generateLevelCipher(self.L, self.Lepoch+1)
        newEllLevelCipher = self.generateLevelCipher(self.ell, self.ellEpoch+1)
        levTableLength = (int)((1+self.cuckooEpsilon)*(2**self.L))
        self.clientAcessStorage = max(self.L+2,self.clientAcessStorage)
        tempD = []
        for i in range(self.N):
            (tmpK,tmpV) = self.oramClientOnlyRead(i)
            tempD.append((tmpK,tmpV))
            if len(tempD)==self.L or i==self.N-1:
                for (k,v) in tempD:
                    tag = self.generateTag(k)
                    shareTag0, shareTag1 = self.secretShareTag(tag)
                    posNowLevel0,posNowLevel1 = self.hashPosition(newLLevelCipher, tag, levTableLength)
                    posEllLevel0,posEllLevel1 = self.hashPosition(newEllLevelCipher, tag, self.ellTableLength)
                    dataMessage0 = cutils.padToSize(str(k),self.AddrSize)+str(v)+cutils.bytesToStr(shareTag0)+cutils.padToSize(str(posNowLevel0),self.PosInTabSize)+cutils.padToSize(str(posNowLevel1),self.PosInTabSize)+cutils.padToSize(str(posEllLevel0),self.PosInTabSize)+cutils.padToSize(str(posEllLevel1),self.PosInTabSize)
                    dataMessage1 = cutils.padToSize(str(k),self.AddrSize)+str(v)+cutils.bytesToStr(shareTag1)+cutils.padToSize(str(posNowLevel0),self.PosInTabSize)+cutils.padToSize(str(posNowLevel1),self.PosInTabSize)+cutils.padToSize(str(posEllLevel0),self.PosInTabSize)+cutils.padToSize(str(posEllLevel1),self.PosInTabSize)
                    """
                    send to server
                    """
                    self.tcpSoc0.sendMessage(dataMessage0)
                    self.tcpSoc1.sendMessage(dataMessage1)
                tempD = []
        
        self.ellEpoch += 1
        self.Lepoch += 1
        self.full = [0 for i in range(self.L-self.ell+1)]
        tmpData = self.receiveM(self.tcpSoc0)
        self.lenEBAndTB = 1
        self.full[0] = int(tmpData[0])
        self.lenES = int(tmpData[1:])
        self.full[self.L-self.ell]=1
        self.ellAccessTimes = 0

    def oramClientOnlyRead(self, a):
        found = False
        tag = self.generateTag(a)
        retrievedEle = (-1,cutils.getRandomStr(self.BlockSize))                    

        """
        Send DPF keys
        """
        #sendStrDPFKeyList0 = ""
        #sendStrDPFKeyList1 = ""
        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)

            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, self.ellTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, self.ellTableLength)
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            #sendStrDPFKeyList0 = sendStrDPFKeyList0+cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0))+cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0))
            #sendStrDPFKeyList1 = sendStrDPFKeyList1+cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1))+cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1))

        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue

            levTableLength = (int)((1+self.cuckooEpsilon)*(1<<lev))
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)

            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, levTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, levTableLength)
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            #sendStrDPFKeyList0 = sendStrDPFKeyList0+cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0))+cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0))
            #sendStrDPFKeyList1 = sendStrDPFKeyList1+cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1))+cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1))

        #self.tcpSoc0.sendMessage(sendStrDPFKeyList0)
        #self.tcpSoc1.sendMessage(sendStrDPFKeyList1)
        
        #receiveMessL0 = self.tcpSoc0.receiveMessage()
        #receiveMessL1 = self.tcpSoc1.receiveMessage()

        #receiveMInd0 = 0
        #receiveMInd1 = 0

        """
        Receive block
        """
        if self.lenEBAndTB>1:
            for _ in range(self.lenEBAndTB-1, 0, -1):
                #recK,recV = int(receiveMessL0[receiveMInd0:receiveMInd0+self.AddrSize]),str(receiveMessL0[receiveMInd0+self.AddrSize:receiveMInd0+self.AddrSize+self.BlockSize])
                #receiveMInd0 += self.AddrSize+self.BlockSize
                tempMess = self.receiveM(self.tcpSoc0)
                recK = int(tempMess[:self.AddrSize])
                recV = str(tempMess[self.AddrSize:])
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    found = True
        
        if self.lenES>1:
            for _ in range(1, self.lenES):
                #recK,recV = int(receiveMessL0[receiveMInd0:receiveMInd0+self.AddrSize]),str(receiveMessL0[receiveMInd0+self.AddrSize:receiveMInd0+self.AddrSize+self.BlockSize])
                #receiveMInd0 += self.AddrSize+self.BlockSize
                tempMess = self.receiveM(self.tcpSoc0)
                recK = int(tempMess[:self.AddrSize])
                recV = str(tempMess[self.AddrSize:])
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    found = True
        
        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)
            
            #temp_share_data_0 = int(receiveMessL0[receiveMInd0:receiveMInd0+self.AddrSize]),str(receiveMessL0[receiveMInd0+self.AddrSize:receiveMInd0+self.AddrSize+self.BlockSize])
            #receiveMInd0 += self.AddrSize+self.BlockSize
            #temp_share_data_1 = int(receiveMessL0[receiveMInd0:receiveMInd0+self.AddrSize]),str(receiveMessL0[receiveMInd0+self.AddrSize:receiveMInd0+self.AddrSize+self.BlockSize])
            #receiveMInd0 += self.AddrSize+self.BlockSize
            #temp_share_data_01 = int(receiveMessL1[receiveMInd1:receiveMInd1+self.AddrSize]),str(receiveMessL1[receiveMInd1+self.AddrSize:receiveMInd1+self.AddrSize+self.BlockSize])
            #receiveMInd1 += self.AddrSize+self.BlockSize
            #temp_share_data_11 = int(receiveMessL1[receiveMInd1:receiveMInd1+self.AddrSize]),str(receiveMessL1[receiveMInd1+self.AddrSize:receiveMInd1+self.AddrSize+self.BlockSize])
            #receiveMInd1 += self.AddrSize+self.BlockSize
            temp_share_data_0 = self.receiveM(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveM(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveM(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveM(self.tcpSoc1)# temp_d11.split( )
            
            temp_data_0 = (cutils.intXor(int(temp_share_data_0[:self.AddrSize]),int(temp_share_data_01[:self.AddrSize])),cutils.strXor(temp_share_data_0[self.AddrSize:],temp_share_data_01[self.AddrSize:]))
            temp_data_1 = (cutils.intXor(int(temp_share_data_1[:self.AddrSize]),int(temp_share_data_11[:self.AddrSize])),cutils.strXor(temp_share_data_1[self.AddrSize:],temp_share_data_11[self.AddrSize:]))
            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_0
                found = True
            if (not found) and temp_data_1[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_1
                found = True

        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)#ET0[lev-self.ell].getPos(levelCipher, tag)
        

            temp_share_data_0 = self.receiveM(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveM(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveM(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveM(self.tcpSoc1)# temp_d11.split( )
            
            temp_data_0 = (cutils.intXor(int(temp_share_data_0[:self.AddrSize]),int(temp_share_data_01[:self.AddrSize])),cutils.strXor(temp_share_data_0[self.AddrSize:],temp_share_data_01[self.AddrSize:]))
            temp_data_1 = (cutils.intXor(int(temp_share_data_1[:self.AddrSize]),int(temp_share_data_11[:self.AddrSize])),cutils.strXor(temp_share_data_1[self.AddrSize:],temp_share_data_11[self.AddrSize:]))
            if (not found) and temp_data_0[0]==a:
                retrievedEle = temp_data_0
                found = True
            if (not found) and temp_data_1[0]==a:
                retrievedEle = temp_data_1
                found = True
        return retrievedEle

if __name__=="__main__":
    BlockSize = 2**5
    NN = 2**10
    A = []
    for i in range(NN):
        A.append((i, cutils.getRandomStr(BlockSize)))
    access_times = 2*NN-1#1#len(A)//2 513#

    coram = ORAMClient(NN, BlockSize, access_times)
    coram.oramClientInitialization(A)
    random.seed(1)
    OP = ["w","r"] 
    #error_times = 0
    pbar = tqdm(total=access_times)
    for i in range(access_times):
        index = random.randint(0,len(A)-1)# random.randint(0,1)#random.randint(0,1)#random.randint(0,len(A)-1)
        k = A[index][0]
        v = cutils.getRandomStr(BlockSize)
        op = random.choice(OP)
        retrievedEle = coram.oramClientAccess(op, k, v)
        #if not retrievedEle==A[index]:
        #    error_times += 1
        if op == "w":
            A[index]=(k,v)
        pbar.update(math.ceil((i+1)/(access_times)))
    pbar.close()
    coram.tcpSoc0.closeConnection()
    coram.tcpSoc1.closeConnection()

    data = {'clientAcessStorage':coram.clientAcessStorage,'bandwidthOfSetup':coram.bandwidthOfSetup/1024,'roundsOfSetup':coram.roundsOfSetup,'timeOfSetup':coram.timeOfSetup,
            'bandwidthOfAccess':coram.bandwidthOfAccess/(access_times*1024),'roundsOfAccess':coram.roundsOfAccess/(access_times),'timeOfAccess':coram.timeOfAccess/access_times,
            'bandwidthOfRebuild':coram.bandwidthOfRebuild/(access_times*1024),'roundsOfRebuild':coram.roundsOfRebuild/(access_times),'timeOfRebuild':coram.timeOfRebuild/access_times}
    pic = open('/home/zxl/local/hORAM/Ours/Result/OursLog_BlockNum{}_Blockize{}.pkl'.format(NN,BlockSize), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()
    


