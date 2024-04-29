import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from tqdm import tqdm
import time
import client
import cutils
import pickle
from cutils import computePosOfHash,computeCurrentTabSize,computeRandomPos

class pORAMClient:
    """
    Ele Form: (int, str())
    """    
    """
    we assume the server stores (addr, value)
    """
    def __init__(self, N, BlockSize, access_times) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Store the public parameters
        totalLevelL: topLevel + mainLevel, from 0,1,2,...,totalLevelL
        has another bottomLevel
        """
        self.BlockSize = BlockSize
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
        self.tagCipher = AES.new(self.tagKey, AES.MODE_ECB, use_aesni=True)

        """
        Send the database size to the server
        """
        self.byteOfCom = 1024
        self.tcpSoc0 = client.tcpClient(client.Addr0, client.Port0, self.byteOfCom)
        self.tcpSoc1 = client.tcpClient(client.Addr1, client.Port1, self.byteOfCom)
        self.tcpSoc0.sendMessage(str(self.N)+" "+str(self.BlockSize)+" "+str(access_times))
        self.tcpSoc0.sendMessage(cutils.bytesToStr(self.tagKey))
        self.tcpSoc0.sendMessage(cutils.bytesToStr(self.levelMasterKey))
        self.tcpSoc1.sendMessage(str(self.N)+" "+str(self.BlockSize)+" "+str(access_times))

        """
        Dummy and Filler Key
        """
        self.dummyAddr = -1
        self.fillerAddr = -2

        """
        Byte size of each sendMessage
        """
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.BinNumSize = math.ceil(math.log10(self.bin_num_each_table_final_level))+1
        self.SizeEachBinSize = math.ceil(math.log10(self.size_each_bin_final_level))+1
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

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def generateLevelCipher(self, level, epoch):
        tmpKey = self.levelMasterCipher.encrypt(self.add_to_16(str(level)+str(epoch)))
        return AES.new(tmpKey, AES.MODE_ECB, use_aesni=True)
    
    def generateTag(self, lev, bucketID, epoch, virAddr):
        return self.tagCipher.encrypt(self.add_to_16(str(lev)+str(bucketID)+str(epoch)+str(virAddr)))[:16]
    
    def getEpoch(self, iLevel):
        return self.accessTimes//((self.numOfBucketPOneD**iLevel)*self.firstBucketSizeK)
   
    def resetOverhead(self):
        """
        Reset the overhead parameters
        """
        self.tcpSoc0.Bandwidth,self.tcpSoc1.Bandwidth = 0,0
        self.tcpSoc0.Rounds,self.tcpSoc1.Rounds = 0,0
        self.tcpSoc0.CurrentState,self.tcpSoc1.CurrentState = 'Init','Init'

    def pOramClientInitialization(self, eleArr):
        """
        Construct the table
        """
        bTime = time.time()
        finalLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        finalLevelSecretKey0 = finalLevelCipher.encrypt(self.add_to_16(str(0)))

        for eleAddrAndVaule in eleArr:
            virAddr, rValue = eleAddrAndVaule
            self.tcpSoc1.sendMessage(cutils.padToSize(str(virAddr),self.AddrSize)+str(rValue)) # str(virAddr)+" "+str(rValue)
            eleLocInTab0 = computePosOfHash(finalLevelSecretKey0,virAddr,self.bin_num_each_table_final_level)
            self.tcpSoc0.sendMessage(cutils.padToSize(str(virAddr),self.AddrSize)+cutils.padToSize(str(eleLocInTab0),self.BinNumSize))

        eTime = time.time()
        """
        Setup overhead
        """
        self.timeOfSetup += eTime-bTime
        self.bandwidthOfSetup += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfSetup += self.tcpSoc0.Rounds/2
        self.resetOverhead()

        tempT,tempB,tempR = self.pOramClientObliviousBuildSim(self.maxLevel,0,self.size_each_bin_final_level,self.bin_num_each_table_final_level)
        self.timeOfSetup += tempT
        self.bandwidthOfSetup += tempB
        self.roundsOfSetup += tempR

        print(self.timeOfSetup,self.bandwidthOfSetup,self.roundsOfSetup)
        self.resetOverhead()

    def pOramClientObliviousBuildSim(self, lev, bucketID, sizeEachBin, binNum):
        """
        To begin using the algorithm, 
        the server S1 has all the non-empty and non-filler elements,
        the server S0 knows all the headers, i.e., the virtual address.
        Construct the first table
        """
        tempMess = self.tcpSoc0.receiveMessage()
        assert tempMess == 'Done'
        self.resetOverhead()
        """
        The client receive the (addr,value) from S1, compute the tag, and send it to the server S0
        """
        bTime = time.time()
        dummyCount = -3
        fillerCount = -sizeEachBin*binNum+dummyCount
        for j in range(2*sizeEachBin*binNum):
            tMess = self.tcpSoc1.receiveMessage()
            tempData = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
            tempHeader = tempData[0]
            tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            if tempHeader==int(self.dummyAddr):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+dummyCount)
                dummyCount -= 1
            elif tempHeader==int(self.fillerAddr):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+fillerCount)
                fillerCount -= 1
            else:
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            self.tcpSoc0.sendMessage(cutils.padToSize(str(tempData[0]),self.AddrSize)+str(tempData[1])+cutils.bytesToStr(tempTag))
            
        """
        Send the table to S1
        """
        for _ in range(2*sizeEachBin*binNum):
            tMess = self.tcpSoc0.receiveMessage()
            tempMess = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:self.AddrSize+self.BlockSize])
            self.tcpSoc1.sendMessage(cutils.padToSize(tempMess[0],self.AddrSize)+tempMess[1])
        eTime = time.time()

        obFile = open('/home/zxl/local/hORAM/KM19/SimBuildResult/N{}_Lev{}.pkl'.format(self.N,lev), 'rb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
        data = pickle.load(obFile)
        obFile.close()
        
        timeOverhead=eTime-bTime+data['timeOfOBuild']
        bandwidthOverhead=self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth+data['bandwidthOfOBuild']
        roundsOverhead=self.tcpSoc0.Rounds/2+data['roundsOfOBuild']

        self.resetOverhead()
        return timeOverhead,bandwidthOverhead,roundsOverhead

    def pOramClientAccess(self, op, virAddr, modifiedValue):
        beginMess0 = self.tcpSoc0.receiveMessage()
        beginMess1 = self.tcpSoc1.receiveMessage()
        assert beginMess0==beginMess1=='Done'
        """
        When access, first retrieve the addr in each level, then use pir to require the actual elements
        """
        self.resetOverhead()
        bTime = time.time()
        found = False
        returnedData = (-1,cutils.getRandomStr)
        modifiedData = (virAddr,modifiedValue)
        """
        First access the top level:
        1. Read all the addr of this level from Server 0;
        2. Modify the addr and send to two servers;
        3. PIR read a location from two server.
        """
        topFound = found
        topLoc = 0
        topLevelLen = self.accessTimes%self.firstBucketSizeK
        if topLevelLen!=0:
            for i in range(topLevelLen):
                accessedAddr = int(self.tcpSoc0.receiveMessage())
                if accessedAddr==virAddr and not topFound and not found:
                    topFound = True
                    found = True
                    topLoc = i
                    accessedAddr = int(self.dummyAddr)
                self.tcpSoc0.sendMessage(str(accessedAddr))
                self.tcpSoc1.sendMessage(str(accessedAddr))

            tempPrfK, tempConvertK, tempK0, tempK1 = cutils.dpfGenKeys(topLoc, topLevelLen)
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK1)))
            tempTopLevelData0 = self.tcpSoc0.receiveMessage()
            tempTopLevelData1 = self.tcpSoc1.receiveMessage()
            tempAccessedValue = cutils.strXor(tempTopLevelData0,tempTopLevelData1)
            if topFound:
                returnedData = (virAddr,tempAccessedValue)
        """
        Then access each bucket in each level, for the bucket of a level, access it in reversed order.
        """
        for lev in range(1,self.totalLevelL+1):
            if self.accessTimes==0:
                break
            currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
            tempModularLargeL = self.accessTimes%(currentLevelEleNum*self.numOfBucketPOneD)
            numberOfFullBucket = tempModularLargeL//currentLevelEleNum
            tempLevelCipher = self.generateLevelCipher(lev,self.getEpoch(lev))
            binNumEachTable,sizeEachBin = computeCurrentTabSize(currentLevelEleNum,self.N)
            """
            bucketID: from d-1,d-2,...,1
            """
            if numberOfFullBucket!=0:
                levelFound = [False, False]
                levelFoundBucketID = 0
                levelFoundBufferLoc = random.randint(0,sizeEachBin-1)
                for bucketID in range(self.numOfBucketPOneD-1,0,-1):
                    if tempModularLargeL!=0 and numberOfFullBucket>=bucketID:
                        currentLevelSecretKey0 = tempLevelCipher.encrypt(self.add_to_16(str(0)+str(bucketID)))
                        currentLevelSecretKey1 = tempLevelCipher.encrypt(self.add_to_16(str(1)+str(bucketID)))
                        if not found:
                            tempLevelLoc0 = computePosOfHash(currentLevelSecretKey0,virAddr,binNumEachTable)
                            tempLevelLoc1 = computePosOfHash(currentLevelSecretKey1,virAddr,binNumEachTable)
                        else:
                            tempLevelLoc0 = random.randint(0,binNumEachTable-1)
                            tempLevelLoc1 = tempLevelLoc0

                        self.tcpSoc0.sendMessage(str(tempLevelLoc0))
                        self.tcpSoc0.sendMessage(str(tempLevelLoc1))
                        self.tcpSoc1.sendMessage(str(tempLevelLoc0))
                        self.tcpSoc1.sendMessage(str(tempLevelLoc1))

                        for i in range(sizeEachBin):
                            accessedAddr0 = int(self.tcpSoc0.receiveMessage())
                            accessedAddr1 = int(self.tcpSoc0.receiveMessage())
                            if accessedAddr0==virAddr and not levelFound[0] and not levelFound[1] and not found:   
                                levelFound[0] = True
                                found = True
                                levelFoundBucketID = numberOfFullBucket-bucketID
                                levelFoundBufferLoc = i
                                accessedAddr0 = int(self.dummyAddr)
                            if accessedAddr1==virAddr and not levelFound[0] and not levelFound[1] and not found:
                                levelFound[1] = True
                                found = True
                                levelFoundBucketID = numberOfFullBucket-bucketID
                                levelFoundBufferLoc = i
                                accessedAddr1 = int(self.dummyAddr)
                            self.tcpSoc0.sendMessage(str(accessedAddr0))
                            self.tcpSoc0.sendMessage(str(accessedAddr1))
                            self.tcpSoc1.sendMessage(str(accessedAddr0))
                            self.tcpSoc1.sendMessage(str(accessedAddr1))

                self.tcpSoc0.sendMessage(str(levelFoundBufferLoc))
                self.tcpSoc1.sendMessage(str(levelFoundBufferLoc))

                tempPrfK, tempConvertK, tempK0, tempK1 = cutils.dpfGenKeys(levelFoundBucketID, numberOfFullBucket)

                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK0)))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK1)))
                tempTopLevelDataFromTable0Server0 = self.tcpSoc0.receiveMessage()
                tempTopLevelDataFromTable1Server0 = self.tcpSoc0.receiveMessage()
                tempTopLevelDataFromTable0Server1 = self.tcpSoc1.receiveMessage()
                tempTopLevelDataFromTable1Server1 = self.tcpSoc1.receiveMessage()

                tempAccessedValue0 = cutils.strXor(tempTopLevelDataFromTable0Server0,tempTopLevelDataFromTable0Server1)
                tempAccessedValue1 = cutils.strXor(tempTopLevelDataFromTable1Server0,tempTopLevelDataFromTable1Server1)
                if levelFound[0]:
                        returnedData = (virAddr,tempAccessedValue0)
                elif levelFound[1]:
                        returnedData = (virAddr,tempAccessedValue1)

        """
        Finally access the maxLevel, the final maxLevel does not require the PIR
        """
        tempLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        binNumEachTable,sizeEachBin = computeCurrentTabSize(self.N,self.N)
        tempsecretkey0 = tempLevelCipher.encrypt(self.add_to_16(str(0)))
        tempsecretkey1 = tempLevelCipher.encrypt(self.add_to_16(str(1)))

        finalLevelFound = [False, False]

        if not found:
            tempLevelLoc0 = computePosOfHash(tempsecretkey0,virAddr,binNumEachTable)
            tempLevelLoc1 = computePosOfHash(tempsecretkey1,virAddr,binNumEachTable)
        else:
            tempLevelLoc0 = random.randint(0,binNumEachTable-1)
            tempLevelLoc1 = random.randint(0,binNumEachTable-1)
        
        self.tcpSoc0.sendMessage(str(tempLevelLoc0))
        self.tcpSoc0.sendMessage(str(tempLevelLoc1))
        self.tcpSoc1.sendMessage(str(tempLevelLoc0))
        self.tcpSoc1.sendMessage(str(tempLevelLoc1))

        for i in range(sizeEachBin):
            tMess0 = self.tcpSoc0.receiveMessage()
            tMess1 = self.tcpSoc0.receiveMessage()
            accessedData0 = int(tMess0[:self.AddrSize]),str(tMess0[self.AddrSize:])
            accessedData1 = int(tMess1[:self.AddrSize]),str(tMess1[self.AddrSize:])
            accessedAddr0 = int(accessedData0[0])
            accessedAddr1 = int(accessedData1[0])
            if accessedAddr0==virAddr and not finalLevelFound[0] and not finalLevelFound[1] and not found:
                finalLevelFound[0] = True
                found = True
                accessedAddr0 = int(self.dummyAddr)
                returnedData = (int(accessedData0[0]), accessedData0[1])
            if accessedAddr1==virAddr and not finalLevelFound[0] and not finalLevelFound[1] and not found:
                finalLevelFound[1] = True
                found = True
                accessedAddr1 = int(self.dummyAddr)
                returnedData = (int(accessedData1[0]), accessedData1[1])
            self.tcpSoc0.sendMessage(str(accessedAddr0))
            self.tcpSoc0.sendMessage(str(accessedAddr1))
            self.tcpSoc1.sendMessage(str(accessedAddr0))
            self.tcpSoc1.sendMessage(str(accessedAddr1))

        """
        Write to the top level
        """
        if op=="read":
            modifiedData=returnedData
        self.tcpSoc0.sendMessage(cutils.padToSize(str(modifiedData[0]),self.AddrSize)+str(modifiedData[1]))
        self.tcpSoc1.sendMessage(cutils.padToSize(str(modifiedData[0]),self.AddrSize)+str(modifiedData[1]))

        eTime = time.time()
        """
        Access overhead
        """
        self.timeOfAccess += eTime-bTime
        self.bandwidthOfAccess += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfAccess += max(self.tcpSoc0.Rounds/2,self.tcpSoc1.Rounds/2)
        self.resetOverhead()
        """
        Rebuild Algorithm
        """
        self.accessTimes += 1
        if self.accessTimes%(self.firstBucketSizeK*(self.numOfBucketPOneD**self.totalLevelL))==0:
            print("RebuildLevel:{}".format(self.maxLevel))
            self.pOramClientRebuildMaxLevel()
        else:
            for i in range(self.totalLevelL,0,-1):
                if self.accessTimes%(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1)))==0:
                    bucID = (self.accessTimes//(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1))))%self.numOfBucketPOneD
                    print("RebuildLevel:{},{}".format(i,bucID))
                    self.pOramClientRebuild(i,bucID)
                    break

        return returnedData

    def pOramClientRebuild(self, lev, bucketID):
        """
        Receive the elements from S0, and send them to S1 while eliminating the empty and filler.
        """
        self.resetOverhead()
        bTime = time.time()
        currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
        tempLevelCipher = self.generateLevelCipher(lev,self.getEpoch(lev))
        tempsecretkey0 = tempLevelCipher.encrypt(self.add_to_16(str(0)+str(bucketID)))
        bin_num_each_table,size_each_bin = computeCurrentTabSize(currentLevelEleNum,self.N)

        numData = int(self.tcpSoc0.receiveMessage())
        for _ in range(numData):
            tMess = self.tcpSoc0.receiveMessage()
            tempData = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
            """
            First remove the filler elements
            """
            if tempData[0]==int(self.dummyAddr) or tempData[0]>=0:
                self.tcpSoc1.sendMessage(cutils.padToSize(str(tempData[0]),self.AddrSize)+str(tempData[1]))

        """
        Receive the header from S1 and send (header, loc) to S0
        """
        for _ in range(currentLevelEleNum):
            tempHeader = int(self.tcpSoc1.receiveMessage())
            eleLocInTab0 = computeRandomPos(bin_num_each_table)
            if tempHeader>=1:
                eleLocInTab0 = computePosOfHash(tempsecretkey0,tempHeader,bin_num_each_table)
            self.tcpSoc0.sendMessage(cutils.padToSize(str(tempHeader),self.AddrSize)+cutils.padToSize(str(eleLocInTab0),self.BinNumSize))

        eTime = time.time()

        """
        Rebuild overhead
        """
        self.timeOfRebuild += eTime-bTime
        self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth+self.tcpSoc1.Bandwidth
        self.roundsOfRebuild += self.tcpSoc0.Rounds/2
        self.resetOverhead()
        tempT,tempB,tempR = self.pOramClientObliviousBuildSim(lev,bucketID,size_each_bin,bin_num_each_table)
        self.timeOfRebuild += tempT
        self.bandwidthOfRebuild += tempB
        self.roundsOfRebuild += tempR
        self.resetOverhead()

    def pOramClientAccessWithoutOverwrite(self, virAddr):
        """
        When access, first retrieve the addr in each level, then use pir to require the actual elements
        """
        found = False
        returnedData = (-1,cutils.getRandomStr(self.BlockSize))
        """
        First access the top level:
        1. Read all the addr of this level from Server 0;
        2. Modify the addr and send to two servers;
        3. PIR read a location from two server.
        """
        topFound = found
        topLoc = 0
        for i in range(self.firstBucketSizeK):
            accessedAddr = int(self.tcpSoc0.receiveMessage())
            if accessedAddr==virAddr and not topFound:
                topFound = True
                found = True
                topLoc = i

        tempPrfK, tempConvertK, tempK0, tempK1 = cutils.dpfGenKeys(topLoc, self.firstBucketSizeK)

        self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK0)))
        self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK1)))
        tMess0 = self.tcpSoc0.receiveMessage()
        tMess1 = self.tcpSoc1.receiveMessage()
        tempTopLevelData0 = int(tMess0[:self.AddrSize]),str(tMess0[self.AddrSize:])
        tempTopLevelData1 = int(tMess1[:self.AddrSize]),str(tMess1[self.AddrSize:])

        tempAccessedData = (cutils.intXor(tempTopLevelData0[0],tempTopLevelData1[0]),cutils.strXor(tempTopLevelData0[1],tempTopLevelData1[1]))
        if topFound:
            assert int(tempAccessedData[0])==virAddr
            returnedData = (int(tempAccessedData[0]),tempAccessedData[1])

        """
        Then access each bucket in each level, for the bucket of a level, access it in reversed order.
        """
        for lev in range(1,self.totalLevelL+1):
            currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
            tempLevelCipher = self.generateLevelCipher(lev,self.getEpoch(lev))
            binNumEachTable,sizeEachBin = computeCurrentTabSize(currentLevelEleNum,self.N)
            """
            bucketID: from d-1,d-2,...,1
            """
            levelFound = False
            levelFoundBucketID = 0
            levelFoundBufferLoc = random.randint(0,sizeEachBin-1)
            for bucketID in range(self.numOfBucketPOneD-1,0,-1):
                currentLevelSecretKey0 = tempLevelCipher.encrypt(self.add_to_16(str(0)+str(bucketID)))
                currentLevelSecretKey1 = tempLevelCipher.encrypt(self.add_to_16(str(1)+str(bucketID)))
                if not found:
                    tempLevelLoc0 = computePosOfHash(currentLevelSecretKey0,virAddr,binNumEachTable)
                    tempLevelLoc1 = computePosOfHash(currentLevelSecretKey1,virAddr,binNumEachTable)
                else:
                    tempLevelLoc0 = random.randint(0,binNumEachTable-1)
                    tempLevelLoc1 = tempLevelLoc0

                self.tcpSoc0.sendMessage(str(tempLevelLoc0))
                self.tcpSoc0.sendMessage(str(tempLevelLoc1))

                for i in range(sizeEachBin):
                    accessedAddr0 = int(self.tcpSoc0.receiveMessage())
                    accessedAddr1 = int(self.tcpSoc0.receiveMessage())
                    if accessedAddr0==virAddr and not levelFound and not found:
                        levelFound = True
                        found = True
                        levelFoundBucketID = levelFoundBucketID-bucketID
                        levelFoundBufferLoc = i
                    if accessedAddr1==virAddr and not levelFound and not found:
                        levelFound = True
                        found = True
                        levelFoundBucketID = levelFoundBucketID-bucketID
                        levelFoundBufferLoc = i

            self.tcpSoc0.sendMessage(str(levelFoundBufferLoc))
            self.tcpSoc1.sendMessage(str(levelFoundBufferLoc))

            tempPrfK, tempConvertK, tempK0, tempK1 = cutils.dpfGenKeys(levelFoundBucketID, self.numOfBucketPOneD-1)

            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((tempPrfK, tempConvertK, tempK1)))
            tMess00 = self.tcpSoc0.receiveMessage()
            tMess10 = self.tcpSoc0.receiveMessage()
            tMess01 = self.tcpSoc1.receiveMessage()
            tMess11 = self.tcpSoc1.receiveMessage()
            tempTopLevelDataFromTable0Server0 = int(tMess00[:self.AddrSize]),str(tMess00[self.AddrSize:])
            tempTopLevelDataFromTable1Server0 = int(tMess10[:self.AddrSize]),str(tMess10[self.AddrSize:])
            tempTopLevelDataFromTable0Server1 = int(tMess01[:self.AddrSize]),str(tMess01[self.AddrSize:])
            tempTopLevelDataFromTable1Server1 = int(tMess11[:self.AddrSize]),str(tMess11[self.AddrSize:])

            tempAccessedData0 = (cutils.intXor(tempTopLevelDataFromTable0Server0[0],tempTopLevelDataFromTable0Server1[0]),cutils.strXor(tempTopLevelDataFromTable0Server0[1],tempTopLevelDataFromTable0Server1[1]))
            tempAccessedData1 = (cutils.intXor(tempTopLevelDataFromTable1Server0[0],tempTopLevelDataFromTable1Server1[0]),cutils.strXor(tempTopLevelDataFromTable1Server0[1],tempTopLevelDataFromTable1Server1[1]))
            if levelFound:
                assert int(tempAccessedData0[0])==virAddr or int(tempAccessedData1[0])==virAddr
                if int(tempAccessedData0[0])==virAddr:
                    returnedData = (int(tempAccessedData0[0]),tempAccessedData0[1])
                elif int(tempAccessedData1[0])==virAddr:
                    returnedData = (int(tempAccessedData1[0]),tempAccessedData1[1])

        """
        Finally access the maxLevel, the final maxLevel does not require the PIR
        """
        tempLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        binNumEachTable,sizeEachBin = computeCurrentTabSize(self.N,self.N)
        tempsecretkey0 = tempLevelCipher.encrypt(self.add_to_16(str(0)))
        tempsecretkey1 = tempLevelCipher.encrypt(self.add_to_16(str(1)))

        finalLevelFound = found

        if not found:
            tempLevelLoc0 = computePosOfHash(tempsecretkey0,virAddr,binNumEachTable)
            tempLevelLoc1 = computePosOfHash(tempsecretkey1,virAddr,binNumEachTable)
        else:
            tempLevelLoc0 = random.randint(0,binNumEachTable-1)
            tempLevelLoc1 = random.randint(0,binNumEachTable-1)
        
        self.tcpSoc0.sendMessage(str(tempLevelLoc0))
        self.tcpSoc0.sendMessage(str(tempLevelLoc1))

        for i in range(sizeEachBin):
            tMess0 = self.tcpSoc0.receiveMessage()
            tMess1 = self.tcpSoc0.receiveMessage()
            accessedData0 = int(tMess0[:self.AddrSize]),str(tMess0[self.AddrSize:])
            accessedData1 = int(tMess1[:self.AddrSize]),str(tMess1[self.AddrSize:])

            accessedAddr0 = int(accessedData0[0])
            accessedAddr1 = int(accessedData1[0])
            if accessedAddr0==virAddr and not finalLevelFound and not found:
                returnedData = (int(accessedData0[0]),accessedData0[1])
                finalLevelFound = True
                found = True
            if accessedAddr1==virAddr and not finalLevelFound and not found:
                returnedData = (int(accessedData1[0]),accessedData1[1])
                finalLevelFound = True
                found = True
        return returnedData

    def pOramClientRebuildMaxLevel(self):
        bTime =time.time()
        finalLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        finalLevelSecretKey0 = finalLevelCipher.encrypt(self.add_to_16(str(0)))

        for i in range(self.N):
            virAddr, rValue = self.pOramClientAccessWithoutOverwrite(i+1)
            self.tcpSoc1.sendMessage(cutils.padToSize(str(virAddr),self.AddrSize)+str(rValue))
            eleLocInTab0 = computePosOfHash(finalLevelSecretKey0,virAddr,self.bin_num_each_table_final_level)
            self.tcpSoc0.sendMessage(cutils.padToSize(str(virAddr),self.AddrSize)+cutils.padToSize(str(eleLocInTab0),self.BinNumSize))
        
        eTime = time.time()
                
        """
        Access overhead
        """
        self.timeOfRebuild += eTime-bTime
        self.bandwidthOfRebuild += self.tcpSoc0.Bandwidth + self.tcpSoc1.Bandwidth
        self.roundsOfRebuild += self.tcpSoc0.Rounds/2
        self.resetOverhead()

        tempT,tempB,tempR = self.pOramClientObliviousBuildSim(self.maxLevel,0,self.size_each_bin_final_level,self.bin_num_each_table_final_level)
        self.timeOfRebuild += tempT
        self.bandwidthOfRebuild += tempB
        self.roundsOfRebuild += tempR
        self.resetOverhead()

if __name__=="__main__":
    random.seed(1)
    blockSize = 2**5
    N = 2**10
    A = []
    for i in range(N):
        A.append((i,cutils.getRandomStr(blockSize)))
    OP = ["w", "r"]
    access_times = 2*N-1
    pkcORAMClient = pORAMClient(N,blockSize,access_times)
    pkcORAMClient.pOramClientInitialization(A)
    
    print(pkcORAMClient.timeOfSetup,pkcORAMClient.roundsOfSetup,pkcORAMClient.bandwidthOfSetup)
    
    error_times = 0
    pbar = tqdm(total=access_times)

    for i in range(access_times):
        index = random.randint(0,len(A)-1)#random.randint(0,1)#random.randint(0,1)#random.randint(0,len(A)-1)
        k = A[index][0]
        v = cutils.getRandomStr(blockSize)
        op = random.choice(OP)
        retrievedEle = pkcORAMClient.pOramClientAccess(op,k,v)
        if not retrievedEle==A[index]:
            error_times += 1
        if op == "w":
            A[index]=(k,v)
        pbar.update(math.ceil((i+1)/(access_times)))
    pkcORAMClient.tcpSoc0.closeConnection()
    pkcORAMClient.tcpSoc1.closeConnection()

    data = {'bandwidthOfSetup':pkcORAMClient.bandwidthOfSetup/1024,'roundsOfSetup':pkcORAMClient.roundsOfSetup,'timeOfSetup':pkcORAMClient.timeOfSetup,
            'bandwidthOfAccess':pkcORAMClient.bandwidthOfAccess/(access_times*1024),'roundsOfAccess':pkcORAMClient.roundsOfAccess/(access_times),'timeOfAccess':pkcORAMClient.timeOfAccess/access_times,
            'bandwidthOfRebuild':pkcORAMClient.bandwidthOfRebuild/(access_times*1024),'roundsOfRebuild':pkcORAMClient.roundsOfRebuild/(access_times),'timeOfRebuild':pkcORAMClient.timeOfRebuild/access_times}
    pic = open('/home/zxl/local/hORAM/KM19/Result/KM19_BlockNum{}_Blockize{}.pkl'.format(N,blockSize), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()
    
    
    




    
    