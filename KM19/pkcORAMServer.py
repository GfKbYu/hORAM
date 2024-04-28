import server
import math
import random
from Cryptodome.Cipher import AES
from cutils import computePosOfHash,computeCurrentTabSize
import copy
import numpy as np
import cutils

class pORAMServer:

    def __init__(self) -> None:
        """
        Receive data size
        """
        self.byteOfComm = 1024
        self.tcpSoc = server.tcpServer(self.byteOfComm)
        tempMess = self.tcpSoc.receiveMessage().split( )
        self.N = int(tempMess[0])
        self.BlockSize = int(tempMess[1])
        self.access_times = int(tempMess[2])
        self.tagKey = cutils.strToBytes(self.tcpSoc.receiveMessage())
        self.levelMasterKey = cutils.strToBytes(self.tcpSoc.receiveMessage())
        self.tagCipher = AES.new(self.tagKey, AES.MODE_ECB, use_aesni=True)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        self.bin_num_each_table_final_level,self.size_each_bin_final_level = computeCurrentTabSize(self.N,self.N)

        """
        Dummy and Filler Key
        """
        self.DummyElementForm = (-1,cutils.getRandomStr(self.BlockSize)) # (virtualAddr,virtualValue)
        self.FillerElementForm = (-2,cutils.getRandomStr(self.BlockSize))
        self.EmptyElementForm = (-3,cutils.getRandomStr(self.BlockSize))
        self.RealElementFlag = 0
        self.DummyElementFlag = 1
        self.FillerElementFlag = 2
        self.EmptyElementFlag = 3
        self.NonExcessFlag = 0
        self.ExcessFlag = 1

        """
        Byte size of each sendMessage
        """
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.BinNumSize = math.ceil(math.log10(self.bin_num_each_table_final_level))+1
        self.SizeEachBinSize = math.ceil(math.log10(self.size_each_bin_final_level))+1
        self.TagSize = 16

        """
        Parameters initilization
        """
        self.firstBucketSizeK = math.ceil(math.log2(self.N))
        self.numOfBucketPOneD = math.ceil(math.log2(self.N))
        self.totalLevelL = math.ceil(math.log2(self.N)/math.log2(math.log2(self.N)))
        self.maxLevel = self.totalLevelL+1
        self.accessTimes = 0
        self.accEpoch = self.firstBucketSizeK*(self.numOfBucketPOneD**self.totalLevelL)
        """
        Construct the structure, 
        The index 0 of mainTable and the index 0 of the bucket in each level is empty, 
        It does not store any elements
        """
        self.topLevelTable = []# [self.EmptyElementForm for _ in range(self.firstBucketSizeK)]
        self.mainTable = [[None for _ in range(self.numOfBucketPOneD)] for i in range(self.totalLevelL+1)]
        self.bottomLevelTable = None

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
      
    def compAndSwap(self, A, ii, jj, dire, flag): # ascending order mess1[2]
        mess1 = A[ii]
        mess2 = A[jj]
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
                A[ii], A[jj] = A[jj], A[ii]
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
                A[ii], A[jj] = A[jj], A[ii]

    def bitonicToOrder(self, A, start, end, dire, flag):
        if end-start>1:
            medium = (end-start)>>1
            for i in range(0, medium):
                self.compAndSwap(A, i+start, i+start+medium, dire, flag)
            self.bitonicToOrder(A, start, start+medium, dire, flag)
            self.bitonicToOrder(A, start+medium, end, dire, flag)

    def bitonicMerge(self, A, start, end, dire, flag):
        if end-start>1:
            medium = (end-start)>>1
            self.bitonicMerge(A, start, start+medium, dire, flag)
            self.bitonicMerge(A, start+medium, end, dire^1, flag)
            self.bitonicToOrder(A, start, end, dire, flag)
   
    def pOramServerInitialization(self):
        """
        Oblivious build the first table: by (virAddr, Value)
        We delete the header matching so that we oblivious build the table based on the (virAddr, Value) instead of only the virAddr
        SendMForm: (addr, binNum, elementType, ExcessOrNot)
        """
        tempHeaderTable0 = [(self.FillerElementForm[0],i//self.size_each_bin_final_level,self.FillerElementFlag,self.NonExcessFlag) for i in range(self.size_each_bin_final_level*self.bin_num_each_table_final_level)]
        tempHeaderTable1 = [(self.FillerElementForm[0],i//self.size_each_bin_final_level,self.FillerElementFlag,self.NonExcessFlag) for i in range(self.size_each_bin_final_level*self.bin_num_each_table_final_level)]
        for _ in range(self.N):
            tempMess = self.tcpSoc.receiveMessage()
            virAddr,eleLocInTab0 = int(tempMess[:self.AddrSize]),int(tempMess[self.AddrSize:])
            tempHeaderTable0.append((virAddr,eleLocInTab0,self.RealElementFlag,self.NonExcessFlag))

        self.bottomLevelTable = ([[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)], [[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)])
        finalLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        finalLevelSecretKey1 = finalLevelCipher.encrypt(self.add_to_16(str(1)))
        self.pOramServerObliviousBuildSim(self.maxLevel, 0, tempHeaderTable0, tempHeaderTable1, self.bottomLevelTable, finalLevelSecretKey1)
    
        print(self.bottomLevelTable)

    def pOramServerObliviousBuildSim(self, lev, bucketID, tempHeaderTable0, tempHeaderTable1, rebuildTable, scretKey1):
        """
        To begin using the algorithm, 
        the server S1 has all the non-empty and non-filler elements,
        the server S0 knows all the headers, i.e., the virtual address.
        """
        binNum = len(rebuildTable[0])
        sizeEachBin = len(rebuildTable[0][0])
        
        """
        Bitonic sort and oblivious construct the first header table
        """
        tempKK = math.ceil(math.log2(len(tempHeaderTable0)))
        while(len(tempHeaderTable0)<2**tempKK):
            tempHeaderTable0.append((self.FillerElementForm[0],len(rebuildTable[0]),self.FillerElementFlag,self.ExcessFlag))
        self.bitonicMerge(tempHeaderTable0,0,len(tempHeaderTable0),1,0)
        tempCount = 0
        tempBinId = 0
        for i in range(len(tempHeaderTable0)):
            tempAddr, binId, eleType, excessOrNot = tempHeaderTable0[i]
            if tempBinId==int(binId):
                if tempCount<sizeEachBin:
                    excessOrNot = str(self.NonExcessFlag)
                    tempCount += 1
                else:
                    excessOrNot = str(self.ExcessFlag)
            else:
                excessOrNot = str(self.NonExcessFlag)
                tempCount = 1
                tempBinId = int(binId)
            tempHeaderTable0[i] = (tempAddr, binId, eleType, excessOrNot)
        self.bitonicMerge(tempHeaderTable0,0,len(tempHeaderTable0),1,1)

        """
        Oblivious build the second header table
        """
        for j in range(len(rebuildTable[0][0])*len(rebuildTable[0]),len(tempHeaderTable0)):
            tempAddr, newBinId, eleType, excessOrNot = tempHeaderTable0[j]
            if eleType==self.RealElementFlag:
                newBinId = computePosOfHash(scretKey1,tempAddr,binNum)
            tempHeaderTable1.append((tempAddr, newBinId, eleType, excessOrNot))

        assert len(tempHeaderTable1)==2**tempKK
        self.bitonicMerge(tempHeaderTable1,0,len(tempHeaderTable1),1,0)
        tempCount = 0
        tempBinId = 0
        for i in range(len(tempHeaderTable1)):
            tempAddr, binId, eleType, excessOrNot = tempHeaderTable1[i]
            if tempBinId==int(binId):
                if tempCount<sizeEachBin:
                    excessOrNot = str(self.NonExcessFlag)
                    tempCount += 1
                else:
                    excessOrNot = str(self.ExcessFlag)
            else:
                excessOrNot = str(self.NonExcessFlag)
                tempCount = 1
                tempBinId = int(binId)
            tempHeaderTable1[i] = (tempAddr, binId, eleType, excessOrNot)
        self.bitonicMerge(tempHeaderTable1,0,len(tempHeaderTable1),1,1)

        tempHeaderTable0 = tempHeaderTable0[:len(rebuildTable[0][0])*len(rebuildTable[0])]
        tempHeaderTable1 = tempHeaderTable1[:len(rebuildTable[1][0])*len(rebuildTable[1])]

        """
        Compute the tag
        """
        dummyCount = -3
        fillerCount = -sizeEachBin*binNum+dummyCount
        for i in range(len(tempHeaderTable0)):
            tempHeader = tempHeaderTable0[i][0]
            tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            if tempHeader==int(self.DummyElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+dummyCount)
                dummyCount -= 1
            elif tempHeader==int(self.FillerElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+fillerCount)
                fillerCount -= 1
            else:
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            tempHeaderTable0[i] = tempTag # only receive the tag

        for j in range(len(tempHeaderTable1)):
            tempHeader = tempHeaderTable1[j][0]
            tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            if tempHeader==int(self.DummyElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+dummyCount)
                dummyCount -= 1
            elif tempHeader==int(self.FillerElementForm[0]):
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader+fillerCount)
                fillerCount -= 1
            else:
                tempTag = self.generateTag(lev,bucketID,self.getEpoch(lev),tempHeader)
            tempHeaderTable1[j] = tempTag # only receive the tag
        
        self.tcpSoc.sendMessage('Done')

        """
        Receive the (Addr, Value) and Tag from the server S1 by the client
        """
        for _ in range(2*len(tempHeaderTable0)):
            tMess = self.tcpSoc.receiveMessage()
            tempRecMess = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:self.AddrSize+self.BlockSize]),cutils.strToBytes(tMess[self.AddrSize+self.BlockSize:])# tempAddr, tempV, tempTag
            if tempRecMess[2] in tempHeaderTable0:
                findInd = tempHeaderTable0.index(tempRecMess[2])
                rowInd = findInd//len(rebuildTable[0][0])
                colInd = findInd%len(rebuildTable[0][0])
                rebuildTable[0][rowInd][colInd] = (int(tempRecMess[0]),str(tempRecMess[1])) 
            elif tempRecMess[2] in tempHeaderTable1:
                findInd = tempHeaderTable1.index(tempRecMess[2])
                rowInd = findInd//len(rebuildTable[1][0])
                colInd = findInd%len(rebuildTable[1][0])
                rebuildTable[1][rowInd][colInd] = (int(tempRecMess[0]),str(tempRecMess[1]))

        """
        Send the rebuild table to the server 1, through the client
        """
        for i in range(len(rebuildTable[0])):
            for j in range(len(rebuildTable[0][i])):
                self.tcpSoc.sendMessage(cutils.padToSize(str(rebuildTable[0][i][j][0]),self.AddrSize)+str(rebuildTable[0][i][j][1]))
   
        for i in range(len(rebuildTable[1])):
            for j in range(len(rebuildTable[1][i])):
                self.tcpSoc.sendMessage(cutils.padToSize(str(rebuildTable[1][i][j][0]),self.AddrSize)+str(rebuildTable[1][i][j][1]))

    def pOramServerAccess(self):
        self.tcpSoc.sendMessage("Done")
        """
        Process the topLevel request
        """
        if len(self.topLevelTable)!=0:
            for i in range(len(self.topLevelTable)):
                self.tcpSoc.sendMessage(str(self.topLevelTable[i][0]))
                self.topLevelTable[i] = (int(self.tcpSoc.receiveMessage()),str(self.topLevelTable[i][1]))
            strDpfK0 = self.tcpSoc.receiveMessage()
            prgK0, convertK0, k0 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.topLevelTable),0,k0)
            val0 = cutils.readData(Bi0,self.topLevelTable)
            self.tcpSoc.sendMessage(val0[1])

        """
        Process the request in each level
        """      
        for lev in range(1,self.totalLevelL+1):
            if self.accessTimes==0:
                break
            currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
            tempModularLargeL = self.accessTimes%(currentLevelEleNum*self.numOfBucketPOneD)
            numberOfFullBucket = tempModularLargeL//currentLevelEleNum
            _,sizeEachBin = computeCurrentTabSize(currentLevelEleNum,self.N)

            tempTable0 = []
            tempTable1 = []
            """
            bucketID: from d-1,d-2,...,1
            """
            if numberOfFullBucket!=0:
                for bucketID in range(self.numOfBucketPOneD-1,0,-1):
                    if tempModularLargeL!=0 and numberOfFullBucket>=bucketID:
                        tempLevelBucketLoc0 = int(self.tcpSoc.receiveMessage())
                        tempLevelBucketLoc1 = int(self.tcpSoc.receiveMessage())
                        tempTable0.append(copy.deepcopy(self.mainTable[lev][bucketID][0][tempLevelBucketLoc0]))
                        tempTable1.append(copy.deepcopy(self.mainTable[lev][bucketID][1][tempLevelBucketLoc1]))
                        for i in range(sizeEachBin):
                            # this lev, this bucket, two tables, a buffer, element in buffer, addr
                            self.tcpSoc.sendMessage(str(self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i][0]))
                            self.tcpSoc.sendMessage(str(self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i][0]))
                            self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i] = (int(self.tcpSoc.receiveMessage()),self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i][1])
                            self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i] = (int(self.tcpSoc.receiveMessage()),self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i][1])

                    else:
                        assert self.mainTable[lev][bucketID]==None

                levelFoundBufferLoc = int(self.tcpSoc.receiveMessage())
                strDpfK0 = self.tcpSoc.receiveMessage()
                prgK0, convertK0, k0 = cutils.strToDpfKeys(strDpfK0)
                Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(tempTable0),0,k0)
                valFromTable0 = cutils.readData(Bi0,np.array(tempTable0)[:,levelFoundBufferLoc].tolist())
                valFromTable1 = cutils.readData(Bi0,np.array(tempTable1)[:,levelFoundBufferLoc].tolist())
                self.tcpSoc.sendMessage(valFromTable0[1])
                self.tcpSoc.sendMessage(valFromTable1[1])

        """
        Finally process the final request
        """
        _,sizeEachBin = computeCurrentTabSize(self.N,self.N)
        tempLevelLoc0 = int(self.tcpSoc.receiveMessage())
        tempLevelLoc1 = int(self.tcpSoc.receiveMessage())
        for i in range(sizeEachBin):
            self.tcpSoc.sendMessage(cutils.padToSize(str(self.bottomLevelTable[0][tempLevelLoc0][i][0]),self.AddrSize)+str(self.bottomLevelTable[0][tempLevelLoc0][i][1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(self.bottomLevelTable[1][tempLevelLoc1][i][0]),self.AddrSize)+str(self.bottomLevelTable[1][tempLevelLoc1][i][1]))
            self.bottomLevelTable[0][tempLevelLoc0][i] = (int(self.tcpSoc.receiveMessage()),self.bottomLevelTable[0][tempLevelLoc0][i][1])
            self.bottomLevelTable[1][tempLevelLoc1][i] = (int(self.tcpSoc.receiveMessage()),self.bottomLevelTable[1][tempLevelLoc1][i][1])

        """
        Write the new elements to top level
        """    
        tMess = self.tcpSoc.receiveMessage()       
        mess = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
        self.topLevelTable.append((int(mess[0]),mess[1]))

        """
        Rebuild Algorithm
        """
        self.accessTimes += 1
        if self.accessTimes%(self.firstBucketSizeK*(self.numOfBucketPOneD**self.totalLevelL))==0:
            print("RebuildLevel:{}".format(self.maxLevel))
            self.pOramServerRebuildMaxLevel()
        else:
            for i in range(self.totalLevelL,0,-1):
                if self.accessTimes%(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1)))==0:
                    bucID = (self.accessTimes//(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1))))%self.numOfBucketPOneD
                    print("RebuildLevel:{},{}".format(i,bucID))
                    self.pOramServerRebuild(i,bucID)
                    break

    def pOramServerRebuild(self, lev, bucketID):
        currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
        bin_num_each_table,size_each_bin = computeCurrentTabSize(currentLevelEleNum,self.N)
        tempLevelCipher = self.generateLevelCipher(lev,self.getEpoch(lev))
        tempsecretkey1 = tempLevelCipher.encrypt(self.add_to_16(str(1)+str(bucketID)))
        
        """
        First, Server S0 sends all the elements to the client
        """
        tempSendDataArray = []
        tempSendDataArray.extend(self.topLevelTable)
        for i in range(1,lev): # Level
            for j in range(1,self.numOfBucketPOneD): # Bucket
                assert self.mainTable[i][j]!=None
                for k in range(len(self.mainTable[i][j][0])):
                    tempSendDataArray.extend(self.mainTable[i][j][0][k])
                    tempSendDataArray.extend(self.mainTable[i][j][1][k])

        random.shuffle(tempSendDataArray)
        self.tcpSoc.sendMessage(str(len(tempSendDataArray)))
        for eData in tempSendDataArray:
            self.tcpSoc.sendMessage(cutils.padToSize(str(eData[0]),self.AddrSize)+str(eData[1]))
        """
        Receive the (header, loc) from the client
        """
        tempHeaderTable0 = [(self.FillerElementForm[0],i//size_each_bin,self.FillerElementFlag,self.NonExcessFlag) for i in range(size_each_bin*bin_num_each_table)]
        tempHeaderTable1 = [(self.FillerElementForm[0],i//size_each_bin,self.FillerElementFlag,self.NonExcessFlag) for i in range(size_each_bin*bin_num_each_table)]
        for _ in range(currentLevelEleNum):
            tMess = self.tcpSoc.receiveMessage()
            virAddr,eleLocInTab0 = int(tMess[:self.AddrSize]),int(tMess[self.AddrSize:])
            tempHeaderTable0.append((virAddr,eleLocInTab0,self.RealElementFlag,self.NonExcessFlag))

        self.mainTable[lev][bucketID] = ([[self.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)], [[self.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)])
        
        self.pOramServerObliviousBuildSim(lev,bucketID,tempHeaderTable0,tempHeaderTable1,self.mainTable[lev][bucketID],tempsecretkey1)
        """
        Clear the previous table
        """
        self.topLevelTable = []
        for i in range(1,lev):
            self.mainTable[i] = [None for _ in range(self.numOfBucketPOneD)]

    def pOramServerAccessWithoutOverwrite(self):
        """
        Process the topLevel request
        """
        for i in range(len(self.topLevelTable)):
            self.tcpSoc.sendMessage(str(self.topLevelTable[i][0]))
        strDpfK0 = self.tcpSoc.receiveMessage()
        prgK0, convertK0, k0 = cutils.strToDpfKeys(strDpfK0)
        Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.topLevelTable),0,k0)
        val0 = cutils.readData(Bi0,self.topLevelTable)
        self.tcpSoc.sendMessage(cutils.padToSize(str(val0[0]),self.AddrSize)+str(val0[1]))

        """
        Process the request in each level
        """      
        for lev in range(1,self.totalLevelL+1):
            currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
            _,sizeEachBin = computeCurrentTabSize(currentLevelEleNum,self.N)

            tempTable0 = []
            tempTable1 = []
            """
            bucketID: from d-1,d-2,...,1
            """
            for bucketID in range(self.numOfBucketPOneD-1,0,-1):
                tempLevelBucketLoc0 = int(self.tcpSoc.receiveMessage())
                tempLevelBucketLoc1 = int(self.tcpSoc.receiveMessage())
                tempTable0.append(copy.deepcopy(self.mainTable[lev][bucketID][0][tempLevelBucketLoc0]))
                tempTable1.append(copy.deepcopy(self.mainTable[lev][bucketID][1][tempLevelBucketLoc1]))
                for i in range(sizeEachBin):
                    # this lev, this bucket, two tables, a buffer, element in buffer, addr
                    self.tcpSoc.sendMessage(self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i][0])
                    self.tcpSoc.sendMessage(self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i][0])

            levelFoundBufferLoc = int(self.tcpSoc.receiveMessage())
            strDpfK0 = self.tcpSoc.receiveMessage()
            prgK0, convertK0, k0 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(tempTable0),0,k0)
            valFromTable0 = cutils.readData(Bi0,np.array(tempTable0)[:,levelFoundBufferLoc].tolist())
            valFromTable1 = cutils.readData(Bi0,np.array(tempTable1)[:,levelFoundBufferLoc].tolist())
            self.tcpSoc.sendMessage(cutils.padToSize(str(valFromTable0[0]),self.AddrSize)+str(valFromTable0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(valFromTable1[0]),self.AddrSize)+str(valFromTable1[1]))

        """
        Finally process the final request
        """
        _,sizeEachBin = computeCurrentTabSize(self.N,self.N)
        tempLevelLoc0 = int(self.tcpSoc.receiveMessage())
        tempLevelLoc1 = int(self.tcpSoc.receiveMessage())
        for i in range(sizeEachBin):
            self.tcpSoc.sendMessage(cutils.padToSize(str(self.bottomLevelTable[0][tempLevelLoc0][i][0]),self.AddrSize)+str(self.bottomLevelTable[0][tempLevelLoc0][i][1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(self.bottomLevelTable[1][tempLevelLoc1][i][0]),self.AddrSize)+str(self.bottomLevelTable[1][tempLevelLoc1][i][1]))

    def pOramServerRebuildMaxLevel(self):
        tempHeaderTable0 = [(self.FillerElementForm[0],i//self.size_each_bin_final_level,self.FillerElementFlag,self.NonExcessFlag) for i in range(self.size_each_bin_final_level*self.bin_num_each_table_final_level)]
        tempHeaderTable1 = [(self.FillerElementForm[0],i//self.size_each_bin_final_level,self.FillerElementFlag,self.NonExcessFlag) for i in range(self.size_each_bin_final_level*self.bin_num_each_table_final_level)]
        for _ in range(self.N):
            self.pOramServerAccessWithoutOverwrite()
            tMess = self.tcpSoc.receiveMessage()
            virAddr,eleLocInTab0 = int(tMess[:self.AddrSize]),int(tMess[self.AddrSize:])
            tempHeaderTable0.append((virAddr,eleLocInTab0,self.RealElementFlag,self.NonExcessFlag))

        self.bottomLevelTable = ([[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)], [[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)])
        finalLevelCipher = self.generateLevelCipher(self.maxLevel,self.getEpoch(self.maxLevel))
        finalLevelSecretKey1 = finalLevelCipher.encrypt(self.add_to_16(str(1)))
        self.pOramServerObliviousBuildSim(self.maxLevel, 0, tempHeaderTable0, tempHeaderTable1, self.bottomLevelTable, finalLevelSecretKey1)
    
        """
        Clear the previous table
        """
        self.topLevelTable = []
        for i in range(1,self.maxLevel):
            self.mainTable[i] = [None for _ in range(self.numOfBucketPOneD)]


if __name__=="__main__":
    pkcORAMServer = pORAMServer()
    pkcORAMServer.pOramServerInitialization()
    for _ in range(pkcORAMServer.access_times):
        pkcORAMServer.pOramServerAccess()
    pkcORAMServer.tcpSoc.closeConnection()



