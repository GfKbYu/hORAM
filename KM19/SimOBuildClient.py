import math
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import time
import client
import cutils
import pickle
from cutils import computePosOfHash,computeCurrentTabSize


class SimOBuildClient:
    """
    Ele Form: (int, str())
    """    
    blockSize = 16
    DummyElementForm = (-1,cutils.getRandomStr(blockSize)) # (virtualAddr,virtualValue)
    FillerElementForm = (-2,cutils.getRandomStr(blockSize))
    EmptyElementForm = (-3,cutils.getRandomStr(blockSize))
    RealElementFlag = 0
    DummyElementFlag = 1
    FillerElementFlag = 2
    EmptyElementFlag = 3
    NonExcessFlag = 0
    ExcessFlag = 1

    """
    we assume the server stores (addr, value)
    """
    def __init__(self, N) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Store the public parameters
        totalLevelL: topLevel + mainLevel, from 0,1,2,...,totalLevelL
        has another bottomLevel
        """
        self.N = N
        self.firstBucketSizeK = math.ceil(math.log2(N))
        self.numOfBucketPOneD = math.ceil(math.log2(N))
        self.totalLevelL = math.ceil(math.log2(N)/math.log2(math.log2(N)))
        self.maxLevel = self.totalLevelL+1
        self.accessTimes = 0
        
        self.accEpoch = self.firstBucketSizeK*(self.numOfBucketPOneD**self.totalLevelL)

        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)


        self.bin_num_each_table_final_level,self.size_each_bin_final_level = computeCurrentTabSize(self.N,self.N)
        self.tagKey = get_random_bytes(16)
        self.tagCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)

        """
        Send the database size to the server
        """
        self.byteOfCom = 1024
        #self.tcpSoc0 = client.tcpClient(client.Addr0, client.Port0, self.byteOfCom)
        #self.tcpSoc0.sendMessage(str(self.N))

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

        self.lp = 0

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def generateLevelCipher(self, level, epoch):
        tmpKey = self.levelMasterCipher.encrypt(self.add_to_16(str(level)+str(epoch)))
        return  AES.new(tmpKey, AES.MODE_ECB, use_aesni=True)
    
    def generateTag(self, lev, bucketID, epoch, virAddr):
        return self.tagCipher.encrypt(self.add_to_16(str(lev)+str(bucketID)+str(epoch)+str(virAddr)))[:16]
    
    def getEpoch(self, iLevel):
        return self.accessTimes//((self.numOfBucketPOneD**iLevel)*self.firstBucketSizeK)
      
    def compAndSwap(self, dire, flag): # ascending order mess1[2]
        self.lp += 1
        m1 = self.tcpSoc0.receiveMessage()
        m2 = self.tcpSoc0.receiveMessage()
        mess1 = m1.split( )
        mess2 = m2.split( )
        if flag == 0:
            if (dire==1 and 
                (int(mess1[1])>int(mess2[1]) or 
                (int(mess1[1])==int(mess2[1]) and int(mess1[2])>int(mess2[2])) or
                (int(mess1[1])==int(mess2[1]) and int(mess1[2])==int(mess2[2])) and int(mess1[3])>int(mess2[3]))
                ) or (
                dire==0 and 
                (int(mess1[1])<int(mess2[1]) or 
                (int(mess1[1])==int(mess2[1]) and int(mess1[2])<int(mess2[2])) or
                (int(mess1[1])==int(mess2[1]) and int(mess1[2])==int(mess2[2])) and int(mess1[3])<int(mess2[3]))
                ):
                self.tcpSoc0.sendMessage(m2)
                self.tcpSoc0.sendMessage(m1)
            else:
                self.tcpSoc0.sendMessage(m1)
                self.tcpSoc0.sendMessage(m2)
        else:
            if (dire==1 and 
                (int(mess1[3])>int(mess2[3]) or 
                (int(mess1[3])==int(mess2[3]) and (
                    (int(mess1[3])==0 and (int(mess1[1])>int(mess2[1]) or (int(mess1[1])==int(mess2[1]) and int(mess1[2])>int(mess2[2])))) or
                    (int(mess1[3])==1 and int(mess1[2])>int(mess2[2]))
                    )
                )
                )
                ) or (dire==0 and 
                (int(mess1[3])<int(mess2[3]) or 
                (int(mess1[3])==int(mess2[3]) and (
                    (int(mess1[3])==0 and (int(mess1[1])<int(mess2[1]) or (int(mess1[1])==int(mess2[1]) and int(mess1[2])<int(mess2[2])))) or
                    (int(mess1[3])==1 and int(mess1[2])<int(mess2[2]))
                    )
                )
                )
                ):
                self.tcpSoc0.sendMessage(m2)
                self.tcpSoc0.sendMessage(m1)
            else:
                self.tcpSoc0.sendMessage(m1)
                self.tcpSoc0.sendMessage(m2)
                  
    def bitonicToOrder(self, lenA, start, end, dire, flag):
        if end-start>1:
            medium = (end-start)>>1
            for i in range(0, medium):
                self.compAndSwap(dire, flag)
            self.bitonicToOrder(lenA, start, start+medium, dire, flag)
            self.bitonicToOrder(lenA, start+medium, end, dire, flag)

    def bitonicMerge(self, lenA, start, end, dire, flag):
        if end-start>1:
            medium = (end-start)>>1
            self.bitonicMerge(lenA, start, start+medium, dire, flag)
            self.bitonicMerge(lenA, start+medium, end, dire^1, flag)
            self.bitonicToOrder(lenA, start, end, dire, flag)

    def pOramClientObliviousBuild(self, lev, bucketID, logTabLen, sizeEachBin, binNum, scretKey1):
        """
        To begin using the algorithm, 
        the server S1 has all the non-empty and non-filler elements,
        the server S0 knows all the headers, i.e., the virtual address.
        Construct the first table
        """
        self.tcpSoc0.Bandwidth = 0
        self.tcpSoc0.Rounds = 0
        
        #print((self.N,lev,0))
        #print(2**logTabLen)
        
        self.bitonicMerge(2**logTabLen,0,2**logTabLen,1,0)
        
        tempCount = 0
        tempBinId = 0
        #pbar = tqdm(total=2**logTabLen)
        #print(2**logTabLen)
        #bbTT = time.time()
        for ii in range(2**logTabLen):
            tempAddr, binId, eleType, excessOrNot = self.tcpSoc0.receiveMessage().split( )
            if tempBinId==int(binId):
                if tempCount<sizeEachBin:
                    excessOrNot = str(SimOBuildClient.NonExcessFlag)
                    tempCount += 1
                else:
                    excessOrNot = str(SimOBuildClient.ExcessFlag)
            else:
                excessOrNot = str(SimOBuildClient.NonExcessFlag)
                tempCount = 1
                tempBinId = int(binId)
            self.tcpSoc0.sendMessage(str(tempAddr)+" "+str(binId)+" "+str(eleType)+" "+str(excessOrNot))
            #pbar.update(math.ceil((ii+1)/(2**logTabLen)))
        self.bitonicMerge(2**logTabLen,0,2**logTabLen,1,1)

        """
        Construct the second table
        """
        #print(2**logTabLen-sizeEachBin*binNum)
        #pbar = tqdm(total=2**logTabLen-sizeEachBin*binNum)
        #bbTT = time.time()
        for ii in range(sizeEachBin*binNum,2**logTabLen):
            tempAddr, newBinId, eleType, excessOrNot = self.tcpSoc0.receiveMessage( ).split( )
            if eleType==SimOBuildClient.RealElementFlag:
                newBinId = computePosOfHash(scretKey1,tempAddr,binNum)
            self.tcpSoc0.sendMessage(str(tempAddr)+" "+str(newBinId)+" "+str(eleType)+" "+str(excessOrNot))
            #pbar.update(math.ceil((ii+1)/(2**logTabLen-sizeEachBin*binNum)))
        #print((self.N,lev,2))
        #eeTT = time.time()
        #print(eeTT-bbTT, simOBClient.tcpSoc0.Bandwidth,((simOBClient.tcpSoc0.Rounds)/2))
        #self.tcpSoc0.Bandwidth = 0
        #self.tcpSoc0.Rounds = 0
        self.bitonicMerge(2**logTabLen,0,2**logTabLen,1,0)

        tempCount = 0
        tempBinId = 0
        #print(2**logTabLen)
        #pbar = tqdm(total=2**logTabLen)
        #bbTT = time.time()
        for ii in range(2**logTabLen):
            tempAddr, binId, eleType, excessOrNot = self.tcpSoc0.receiveMessage().split( )
            if tempBinId==int(binId):
                if tempCount<sizeEachBin:
                    excessOrNot = str(SimOBuildClient.NonExcessFlag)
                    tempCount += 1
                else:
                    excessOrNot = str(SimOBuildClient.ExcessFlag)
            else:
                excessOrNot = str(SimOBuildClient.NonExcessFlag)
                tempCount = 1
                tempBinId = int(binId)
            self.tcpSoc0.sendMessage(str(tempAddr)+" "+str(binId)+" "+str(eleType)+" "+str(excessOrNot))
            #pbar.update(math.ceil((ii+1)/(2**logTabLen)))
        #print((self.N,lev,3))
        #eeTT = time.time()
        #print(eeTT-bbTT, simOBClient.tcpSoc0.Bandwidth,((simOBClient.tcpSoc0.Rounds)/2))
        #self.tcpSoc0.Bandwidth = 0
        #self.tcpSoc0.Rounds = 0
               
        self.bitonicMerge(2**logTabLen,0,2**logTabLen,1,1)

        """
        The client receive the header and compute the tag
        """
        dummyCount = -3
        fillerCount = -sizeEachBin*binNum+dummyCount
        #print(2*sizeEachBin*binNum)
        #pbar = tqdm(total=2*sizeEachBin*binNum)
        #bbTT = time.time()
        for ii in range(2*sizeEachBin*binNum):
            tempHeader = int(self.tcpSoc0.receiveMessage())
            tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            if tempHeader==int(SimOBuildClient.DummyElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+dummyCount)
                dummyCount -= 1
            elif tempHeader==int(SimOBuildClient.FillerElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+fillerCount)
                fillerCount -= 1
            else:
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            self.tcpSoc0.sendMessage(cutils.bytesToStr(tempTag))
            #pbar.update(math.ceil((ii+1)/(2*sizeEachBin*binNum)))
        #eeTT = time.time()
        #print()
        #print(eeTT-bbTT, simOBClient.tcpSoc0.Bandwidth,((simOBClient.tcpSoc0.Rounds)/2))
        #self.tcpSoc0.Bandwidth = 0
        #self.tcpSoc0.Rounds = 0

if __name__=='__main__':

    #data = {'timeOfOBuild':6576072,'bandwidthOfOBuild':540989440,'roundsOfOBuild':3883412}
    #data = {'timeOfOBuild':116585,'bandwidthOfOBuild':540989440,'roundsOfOBuild':3883412}
    #pic = open('/home/zxl/local/hORAM/KM19/SimBuildResult/N{}_Lev{}.pkl'.format(2**8,4), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    #pickle.dump(data,pic)
    #pic.close()

    NList = [2**10]
    "Bitonic for 32"
    timeConsume = 28.106075048446655
    bandConsume = 7680
    roundsConsume = 240.0
    for N in NList:
        "Level is from 0,1,2,...,totalLevelL"
        simOBClient = SimOBuildClient(N)
        print(1,simOBClient.maxLevel)
        for lev in range(1,simOBClient.maxLevel+1):
            #simOBClient.tcpSoc0.Bandwidth = 0
            #simOBClient.tcpSoc0.Rounds = 0
            bucketID = 0
            currentLevelEleNum = (simOBClient.numOfBucketPOneD**(lev-1))*simOBClient.firstBucketSizeK
            tempLevelCipher = simOBClient.generateLevelCipher(lev,simOBClient.getEpoch(lev))
            tempsecretkey0 = tempLevelCipher.encrypt(simOBClient.add_to_16(str(0)+str(bucketID)))
            tempsecretkey1 = tempLevelCipher.encrypt(simOBClient.add_to_16(str(1)+str(bucketID)))
            bin_num_each_table,size_each_bin = computeCurrentTabSize(currentLevelEleNum,simOBClient.N)
            logTabLen = math.ceil(math.log2(size_each_bin*bin_num_each_table+currentLevelEleNum))
        
            print(bin_num_each_table,size_each_bin,logTabLen)
            #bTime = time.time()
            #simOBClient.pOramClientObliviousBuild(lev,bucketID,logTabLen,size_each_bin,bin_num_each_table,tempsecretkey1)
            #eTime = time.time()

            #data = {'timeOfOBuild':eTime-bTime,'bandwidthOfOBuild':simOBClient.tcpSoc0.Bandwidth,'roundsOfOBuild':simOBClient.tcpSoc0.Rounds}
            #pic = open('/home/zxl/local/hORAM/KM19/SimBuildResult/N{}_LevLev{}.pkl'.format(N,lev), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
            #pickle.dump(data,pic)
            #pic.close()
        