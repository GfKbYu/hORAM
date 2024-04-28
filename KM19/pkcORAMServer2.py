import server
import math
import random
from cutils import computeCurrentTabSize
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

    def pOramServer2Initialization(self):
        self.bottomLevelTable = ([[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)], [[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)])
        
        tempDataTable = []
        for _ in range(self.N):
            tempMess = self.tcpSoc.receiveMessage()
            virAddr,rValue = int(tempMess[:self.AddrSize]),str(tempMess[self.AddrSize:])
            tempDataTable.append((int(virAddr),str(rValue)))
        while len(tempDataTable)<2*self.size_each_bin_final_level*self.bin_num_each_table_final_level:
            tempDataTable.append(self.FillerElementForm)
        random.shuffle(tempDataTable)
        self.pOramServer2ObliviousBuild(tempDataTable,self.bottomLevelTable)

        print(self.bottomLevelTable)

    def pOramServer2ObliviousBuild(self, tempDataTable, rebuildTable):
        """
        The server2 began to send the (addr,value) of tempTable with full length to the server 1
        """
        """
        Send the (addr, value) to server S0, through the client
        """
        for eData in tempDataTable:
            self.tcpSoc.sendMessage(cutils.padToSize(str(eData[0]),self.AddrSize)+str(eData[1]))

        """
        Receive the constructed table
        """
        for i in range(len(rebuildTable[0])):
            for j in range(len(rebuildTable[0][i])):
                tMess = self.tcpSoc.receiveMessage()
                tempAddr, tempValue = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
                rebuildTable[0][i][j] = (int(tempAddr), str(tempValue))
   
        for i in range(len(rebuildTable[1])):
            for j in range(len(rebuildTable[1][i])):
                tMess = self.tcpSoc.receiveMessage()
                tempAddr, tempValue = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
                rebuildTable[1][i][j] = (int(tempAddr), str(tempValue))
        
    def pOramServer2Access(self):
        self.tcpSoc.sendMessage("Done")
        """
        Process the topLevel request
        """
        if len(self.topLevelTable)!=0:
            for i in range(len(self.topLevelTable)):
                self.topLevelTable[i] = (int(self.tcpSoc.receiveMessage()),self.topLevelTable[i][1])
            strDpfK1 = self.tcpSoc.receiveMessage()
            prgK1, convertK1, k1 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.topLevelTable),1,k1)
            val1 = cutils.readData(Bi1,self.topLevelTable)
            self.tcpSoc.sendMessage(val1[1])
            
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
                            self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i] = (int(self.tcpSoc.receiveMessage()),self.mainTable[lev][bucketID][0][tempLevelBucketLoc0][i][1])
                            self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i] = (int(self.tcpSoc.receiveMessage()),self.mainTable[lev][bucketID][1][tempLevelBucketLoc1][i][1])

                    else:
                        assert self.mainTable[lev][bucketID]==None

                levelFoundBufferLoc = int(self.tcpSoc.receiveMessage())
                strDpfK1 = self.tcpSoc.receiveMessage()
                prgK1, convertK1, k1 = cutils.strToDpfKeys(strDpfK1)
                Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(tempTable0),1,k1)
                valFromTable0 = cutils.readData(Bi1,np.array(tempTable0)[:,levelFoundBufferLoc].tolist())
                valFromTable1 = cutils.readData(Bi1,np.array(tempTable1)[:,levelFoundBufferLoc].tolist())
                self.tcpSoc.sendMessage(valFromTable0[1])
                self.tcpSoc.sendMessage(valFromTable1[1])

        """
        Finally process the final request
        """
        _,sizeEachBin = computeCurrentTabSize(self.N,self.N)
        tempLevelLoc0 = int(self.tcpSoc.receiveMessage())
        tempLevelLoc1 = int(self.tcpSoc.receiveMessage())
        for i in range(sizeEachBin):
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
            self.pOramServer2RebuildMaxLevel()
        else:
            for i in range(self.totalLevelL,0,-1):
                if self.accessTimes%(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1)))==0:
                    bucID = (self.accessTimes//(self.firstBucketSizeK*(self.numOfBucketPOneD**(i-1))))%self.numOfBucketPOneD
                    print("RebuildLevel:{},{}".format(i,bucID))
                    self.pOramServer2Rebuild(i,bucID)
                    break

    def pOramServer2Rebuild(self, lev, bucketID):
        """
        Receive the elements and send the header to S0, through the client
        """
        currentLevelEleNum = (self.numOfBucketPOneD**(lev-1))*self.firstBucketSizeK
        bin_num_each_table,size_each_bin = computeCurrentTabSize(currentLevelEleNum,self.N)
        tempSendDataArray = []
        for _ in range(currentLevelEleNum):
            tMess = self.tcpSoc.receiveMessage()
            tempMessData = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
            tempSendDataArray.append((int(tempMessData[0]),str(tempMessData[1])))
        random.shuffle(tempSendDataArray)
        for i in range(len(tempSendDataArray)):
            self.tcpSoc.sendMessage(str(tempSendDataArray[i][0]))
        
        """
        Send the (addr, value) to server S0, through the client
        """
        while len(tempSendDataArray)<2*size_each_bin*bin_num_each_table:
            tempSendDataArray.append(self.FillerElementForm)
        random.shuffle(tempSendDataArray)
        self.mainTable[lev][bucketID] = ([[self.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)], [[self.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)])
        
        self.pOramServer2ObliviousBuild(tempSendDataArray,self.mainTable[lev][bucketID])

        """
        Clear the previous table
        """
        self.topLevelTable = []
        for i in range(1,lev):
            self.mainTable[i] = [None for _ in range(self.numOfBucketPOneD)]

    def pOramServer2AccessWithoutOverwrite(self):
        """
        Process the topLevel request
        """
        strDpfK1 = self.tcpSoc.receiveMessage()
        prgK1, convertK1, k1 = cutils.strToDpfKeys(strDpfK1)
        Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.topLevelTable),1,k1)
        val1 = cutils.readData(Bi1,self.topLevelTable)
        self.tcpSoc.sendMessage(cutils.padToSize(str(val1[0]),self.AddrSize)+str(val1[1]))

        """
        Process the request in each level
        """      
        for lev in range(1,self.totalLevelL+1):
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
                
            levelFoundBufferLoc = int(self.tcpSoc.receiveMessage())
            strDpfK1 = self.tcpSoc.receiveMessage()
            prgK1, convertK1, k1 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(tempTable0),1,k1)
            valFromTable0 = cutils.readData(Bi1,np.array(tempTable0)[:,levelFoundBufferLoc].tolist())
            valFromTable1 = cutils.readData(Bi1,np.array(tempTable1)[:,levelFoundBufferLoc].tolist())
            self.tcpSoc.sendMessage(cutils.padToSize(str(valFromTable0[0]),self.AddrSize)+str(valFromTable0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(valFromTable1[0]),self.AddrSize)+str(valFromTable1[1]))


    def pOramServer2RebuildMaxLevel(self):
        self.bottomLevelTable = ([[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)], [[self.FillerElementForm for _ in range(self.size_each_bin_final_level)] for _ in range(self.bin_num_each_table_final_level)])
        tempDataTable = []
        for _ in range(self.N):
            self.pOramServer2AccessWithoutOverwrite()
            tMess = self.tcpSoc.receiveMessage()
            virAddr,rValue = int(tMess[:self.AddrSize]),str(tMess[self.AddrSize:])
            tempDataTable.append((int(virAddr),str(rValue)))
        while len(tempDataTable)<2*self.size_each_bin_final_level*self.bin_num_each_table_final_level:
            tempDataTable.append(self.FillerElementForm)
        random.shuffle(tempDataTable)

        self.pOramServer2ObliviousBuild(tempDataTable,self.bottomLevelTable)
        """
        Clear the previous table
        """
        self.topLevelTable = []
        for i in range(1,self.maxLevel):
            self.mainTable[i] = [None for _ in range(self.numOfBucketPOneD)]

if __name__=="__main__":
    pkcORAMServer2 = pORAMServer()
    pkcORAMServer2.pOramServer2Initialization()
    for _ in range(pkcORAMServer2.access_times):
        pkcORAMServer2.pOramServer2Access()
    pkcORAMServer2.tcpSoc.closeConnection()

