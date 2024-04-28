import server
import math
from cutils import computeCurrentTabSize
import cutils

class SimOBuildServer:
    blockSize = 32
    DummyElementForm = (-1,cutils.getRandomStr(blockSize)) # (virtualAddr,virtualValue)
    FillerElementForm = (-2,cutils.getRandomStr(blockSize))
    EmptyElementForm = (-3,cutils.getRandomStr(blockSize))
    RealElementFlag = 0
    DummyElementFlag = 1
    FillerElementFlag = 2
    EmptyElementFlag = 3
    NonExcessFlag = 0
    ExcessFlag = 1

    def __init__(self) -> None:
        """
        Receive data size
        """
        self.byteOfComm = 1024
        self.tcpSoc = server.tcpServer(self.byteOfComm)
        self.N = int(self.tcpSoc.receiveMessage())
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
        self.topLevelTable = []# [SimOBuildServer.EmptyElementForm for _ in range(self.firstBucketSizeK)]
        self.mainTable = [[None for _ in range(self.numOfBucketPOneD)] for i in range(self.totalLevelL+1)]
        self.bottomLevelTable = None
        self.bin_num_each_table_final_level,self.size_each_bin_final_level = computeCurrentTabSize(self.N,self.N)
    
    def compAndSwap(self, A, i, j): # ascending order
        """
        Addr, Location, EleType, ExcessOrNot  
        """
        self.tcpSoc.sendMessage(str(A[i][0])+" "+str(A[i][1])+" "+str(A[i][2])+" "+str(A[i][3]))
        self.tcpSoc.sendMessage(str(A[j][0])+" "+str(A[j][1])+" "+str(A[j][2])+" "+str(A[j][3]))

        mess1 = self.tcpSoc.receiveMessage().split( )
        mess2 = self.tcpSoc.receiveMessage().split( )
        A[i] = (int(mess1[0]),int(mess1[1]),int(mess1[2]),int(mess1[3]))
        A[j] = (int(mess2[0]),int(mess2[1]),int(mess2[2]),int(mess2[3]))
            
    def bitonicToOrder(self, A, start, end, dire):
        if end-start>1:
            medium = (end-start)>>1
            for i in range(0, medium):
                self.compAndSwap(A, i+start, i+start+medium)
            self.bitonicToOrder(A, start, start+medium, dire)
            self.bitonicToOrder(A, start+medium, end, dire)

    def bitonicMerge(self, A, start, end, dire):
        if end-start>1:
            medium = (end-start)>>1
            self.bitonicMerge(A, start, start+medium, dire)
            self.bitonicMerge(A, start+medium, end, dire^1)
            self.bitonicToOrder(A, start, end, dire)
            
    def pOramServerObliviousBuild(self, tempHeaderTable0, tempHeaderTable1, rebuildTable):
        """
        To begin using the algorithm, 
        the server S1 has all the non-empty and non-filler elements,
        the server S0 knows all the headers, i.e., the virtual address.
        """
        
        """
        Bitonic sort and oblivious construct the first header table
        """
        tempKK = math.ceil(math.log2(len(tempHeaderTable0)))
        while(len(tempHeaderTable0)<2**tempKK):
            tempHeaderTable0.append((SimOBuildServer.FillerElementForm[0],len(rebuildTable[0]),SimOBuildServer.FillerElementFlag,SimOBuildServer.ExcessFlag))
        #self.bitonicMerge(tempHeaderTable0,0,len(tempHeaderTable0),1)

        print(len(tempHeaderTable0))
        for tempInd in range(len(tempHeaderTable0)):
            self.tcpSoc.sendMessage(str(tempHeaderTable0[tempInd][0])+" "+str(tempHeaderTable0[tempInd][1])+" "+str(tempHeaderTable0[tempInd][2])+" "+str(tempHeaderTable0[tempInd][3]))
            k1,k2,k3,k4 = self.tcpSoc.receiveMessage().split( )
            tempHeaderTable0[tempInd] = (k1,k2,k3,k4)

        #self.bitonicMerge(tempHeaderTable0,0,len(tempHeaderTable0),1)

        """
        Oblivious build the second header table
        """
        
        print(len(tempHeaderTable0)-len(rebuildTable[0][0])*len(rebuildTable[0]))
        for j in range(len(rebuildTable[0][0])*len(rebuildTable[0]),len(tempHeaderTable0)):
            self.tcpSoc.sendMessage(str(tempHeaderTable0[j][0])+" "+str(tempHeaderTable0[j][1])+" "+str(tempHeaderTable0[j][2])+" "+str(tempHeaderTable0[j][3]))
            k1,k2,k3,k4 = self.tcpSoc.receiveMessage().split( )
            tempHeaderTable1.append((k1,k2,k3,k4))

        assert len(tempHeaderTable1)==2**tempKK
        #self.bitonicMerge(tempHeaderTable1,0,len(tempHeaderTable1),1)
        print(len(tempHeaderTable1))
        for tempInd in range(len(tempHeaderTable1)):
            self.tcpSoc.sendMessage(str(tempHeaderTable1[tempInd][0])+" "+str(tempHeaderTable1[tempInd][1])+" "+str(tempHeaderTable1[tempInd][2])+" "+str(tempHeaderTable1[tempInd][3]))
            k1,k2,k3,k4 = self.tcpSoc.receiveMessage().split( )
            tempHeaderTable1[tempInd] = (k1,k2,k3,k4)

        #self.bitonicMerge(tempHeaderTable1,0,len(tempHeaderTable1),1)

        tempHeaderTable0 = tempHeaderTable0[:len(rebuildTable[0][0])*len(rebuildTable[0])]
        tempHeaderTable1 = tempHeaderTable1[:len(rebuildTable[1][0])*len(rebuildTable[1])]

        """
        S0 send the header in table to client and receive the tag
        """
        print(len(tempHeaderTable0)+len(tempHeaderTable1))
        for i in range(len(tempHeaderTable0)):
            self.tcpSoc.sendMessage(str(tempHeaderTable0[i][0]))
            tempHeaderTable0[i] = self.tcpSoc.receiveMessage() # only receive the tag

        for j in range(len(tempHeaderTable1)):
            self.tcpSoc.sendMessage(str(tempHeaderTable1[j][0]))
            tempHeaderTable1[j] = self.tcpSoc.receiveMessage() # only receive the tag

if __name__=='__main__':
    NList = [2**8]
    for N in NList:
        "Level is from 0,1,2,...,totalLevelL"
        SimOServer = SimOBuildServer()
        for lev in range(1,SimOServer.maxLevel+1):
            bucketID = 0
            currentLevelEleNum = (SimOServer.numOfBucketPOneD**(lev-1))*SimOServer.firstBucketSizeK
            bin_num_each_table,size_each_bin = computeCurrentTabSize(currentLevelEleNum,SimOServer.N)
            logTabLen = math.ceil(math.log2(size_each_bin*bin_num_each_table+currentLevelEleNum))

            tempHeaderTable0 = [(SimOBuildServer.FillerElementForm[0],i//size_each_bin,SimOBuildServer.FillerElementFlag,SimOBuildServer.NonExcessFlag) for i in range(size_each_bin*bin_num_each_table+currentLevelEleNum)]
            tempHeaderTable1 = [(SimOBuildServer.FillerElementForm[0],i//size_each_bin,SimOBuildServer.FillerElementFlag,SimOBuildServer.NonExcessFlag) for i in range(size_each_bin*bin_num_each_table)]
           
            rebuildLevTable = ([[SimOBuildServer.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)], [[SimOBuildServer.FillerElementForm for _ in range(size_each_bin)] for _ in range(bin_num_each_table)])
            SimOServer.pOramServerObliviousBuild(tempHeaderTable0, tempHeaderTable1, rebuildLevTable)

