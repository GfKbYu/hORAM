import server
import math
import gutils


class aORAMServer:
    def __init__(self) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Receive data size
        """
        self.byteOfComm = 1024
        self.tcpSoc = server.tcpServer2(self.byteOfComm)
        tempMess = self.tcpSoc.receiveMessage().split( )
        self.N = int(tempMess[0])
        self.BlockSize = int(tempMess[1])
        self.access_times = int(tempMess[2])
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.PosSize = math.ceil(math.log10(self.N))+1

        self.A = 1
        self.Z = 2
        self.ctr = -1
        self.treeDepth = math.ceil(math.log2(self.N))# 1,2,...,treedepth
        self.leafNum = self.N

        self.emptyForm = (-1,gutils.getRandomStr(self.BlockSize))

        self.Tree = [[[self.emptyForm for _ in range(self.Z)] for j in range(2**i)] for i in range(self.treeDepth+1)]

    def unpackStrToKVPos(self,mess):
        return (int(mess[:self.AddrSize]),str(mess[self.AddrSize:self.AddrSize+self.BlockSize]),int(mess[self.AddrSize+self.BlockSize:]))
    
    def packKVToStr(self,k,v):
        return gutils.padToSize(str(k),self.AddrSize)+str(v)    
    
    def unpackStrToKV(self,mess):
        return (int(mess[:self.AddrSize]),str(mess[self.AddrSize:]))
    
    def aORAMServerInitialization(self):
        for _ in range(self.N):
            (k,v,leafPos) = self.unpackStrToKVPos(self.tcpSoc.receiveMessage())
            tempWriteFlag = False
            for i in range(self.treeDepth,0,-1):
                nowLevPos = gutils.leafPosTolevPos(leafPos,i,self.treeDepth)
                for j in range(self.Z):
                    if self.Tree[i][nowLevPos][j]==self.emptyForm:
                        self.Tree[i][nowLevPos][j]=(k,v)
                        tempWriteFlag = True
                        break
                if tempWriteFlag:
                    break
       
    def aORAMServerAccess(self):
        self.tcpSoc.sendMessage("Done")
        pk,ck,k1 = gutils.strToDpfKeys(self.tcpSoc.receiveMessage())
        Bi = gutils.dpfEvalAll(pk,ck,self.leafNum,1,k1)
        tempBiList = [[-1 for j in range(2**i)] for i in range(self.treeDepth+1)]
        tempBiList[self.treeDepth]=Bi

        for i in range(self.treeDepth-1,0,-1):
            for j in range(len(tempBiList[i])):
                tempBiList[i][j]=tempBiList[i+1][2*j]^tempBiList[i+1][2*j+1]
        
        for i in range(1,self.treeDepth+1): 
            for z in range(self.Z):
                (tmpK,tmpV) = (0,gutils.strXor(self.emptyForm[1],self.emptyForm[1]))
                for j in range(len(self.Tree[i])):
                    (tmpK,tmpV) = (gutils.intXor(tmpK,tempBiList[i][j]*self.Tree[i][j][z][0]), gutils.strXor(tmpV,gutils.strMul01(tempBiList[i][j],self.Tree[i][j][z][1])))
                self.tcpSoc.sendMessage(self.packKVToStr(tmpK,tmpV))

        self.ctr = (self.ctr+1)%self.leafNum
        if self.ctr%self.A==0:
            self.aORAMServerEvict()             

    def aORAMServerEvict(self):
        leafPos = gutils.reverseBit(self.ctr,self.treeDepth)
   
        for i in range(1,self.treeDepth+1):
            pos = gutils.leafPosTolevPos(leafPos,i,self.treeDepth)#evictPath//(self.treeDepth-i)
            for j in range(self.Z):
                self.Tree[i][pos][j]=self.unpackStrToKV(self.tcpSoc.receiveMessage())

if __name__=="__main__":

    soram = aORAMServer()
    soram.aORAMServerInitialization()
    for i in range(soram.access_times):
        retrievedEle = soram.aORAMServerAccess()
    soram.tcpSoc.closeConnection()