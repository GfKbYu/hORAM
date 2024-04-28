import math
import server
import cutils
import time
import copy

class ORAMServer:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    Assume the block can accomodate (tag, ele)
    """
    def __init__(self) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        
        self.byteOfCom = 1024
        self.tcpSoc = server.tcpServer2(self.byteOfCom)

        tempMess = self.tcpSoc.receiveMessage().split( )
        self.N = int(tempMess[0])
        self.BlockSize = int(tempMess[1])
        self.access_times = int(tempMess[2])

        self.L = math.ceil(math.log2(self.N))
        self.ell = min(self.L-1, math.ceil(2*math.log2(math.log2(self.N)))) # N: 16, 64, 64*4
        self.ctr = 0
        self.full = [0 for _ in range(self.L-self.ell+1)] # 1,2,...
        """
        Store in servers, position 0 of all the table is dummy
        """
        self.ellAccessTimes = 0
        
        self.cuckooAlpha = math.ceil(math.log2(self.N))
        self.cuckooEpsilon = 0.01
        self.threshold_evict = self.cuckooAlpha*math.ceil(math.log2(self.N))

        self.eleEmptyForm = ("-1",cutils.getRandomStr(self.BlockSize)) # (k,v): str, str
        self.tagEmptyForm = bytes(16) # tag: bytes-16

        self.ecEllLength = 2**(self.ell+1)+math.ceil(math.log2(self.N))*(self.L-self.ell)
        self.LTableLength = (int)((1+self.cuckooEpsilon)*(2**self.L))

        self.EC = [[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*self.ecEllLength))] for j in range(2)] # store (a, v, levelndex): (str, str, str)
        self.ES = [self.eleEmptyForm]
        self.EB = [self.eleEmptyForm]

        self.TC = [[self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*self.ecEllLength))] for j in range(2)] # store (tag, levelIndex): (16-byte, str)
        self.TS = [self.tagEmptyForm]
        self.TB = [self.tagEmptyForm]


        self.ET = [[[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))],[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))]] for j in range(self.L-self.ell+1)]
        self.TT = [[[self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))], [self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))]] for j in range(self.L-self.ell+1)]
        
        
        self.posDict = [[{},{}] for _ in range(self.L-self.ell+1)]


        """
        Byte size of each sendMessage
        """
        self.AddrSize = math.ceil(math.log10(self.N))+1
        self.PosInTabSize = math.ceil(math.log10(self.LTableLength))+1
        self.TagSize = 16
        self.BSSize = 2
        self.FullFlagSize = 1

    def receiveMAndSplit(self):
        return self.tcpSoc.receiveMessage().split( )
        
    def receiveM(self):
        return self.tcpSoc.receiveMessage()

    def writeToTableEll(self, kv,shareTag,ellPos0,ellPos1):
        self.full[0]=1
        ins_preservedV = (kv[0],kv[1])
        ins_preservedTag = shareTag
        ins_table_num = 0
        #Loc = [self.hash_one(comp_tag), self.hash_two(comp_tag)]
        kickedPos = -1
        writePos = -1
        Loc = [ellPos0, ellPos1]
        #kicked_V = self.emptyEleForm
        if self.EC[0][Loc[0]]==self.eleEmptyForm:
            self.EC[0][Loc[0]]=ins_preservedV
            self.TC[0][Loc[0]]=ins_preservedTag
            self.posDict[0][0][Loc[0]]=Loc[1]
            return
        elif self.EC[1][Loc[1]]==self.eleEmptyForm:
            self.EC[1][Loc[1]]=ins_preservedV
            self.TC[1][Loc[1]]=ins_preservedTag
            self.posDict[0][1][Loc[1]]=Loc[0]
            return
        else:
            ins_table_num = 0
            kickedV = self.EC[ins_table_num][Loc[ins_table_num]]
            kickedTag = self.TC[ins_table_num][Loc[ins_table_num]] # kicked
            kickedPos = Loc[ins_table_num]
            writePos = self.posDict[0][ins_table_num][Loc[ins_table_num]]

            self.EC[ins_table_num][Loc[ins_table_num]]=ins_preservedV
            self.TC[ins_table_num][Loc[ins_table_num]]=ins_preservedTag
            self.posDict[0][ins_table_num][Loc[ins_table_num]] = Loc[ins_table_num^1]
            ins_table_num = ins_table_num^1

        count = 0
        while count<self.threshold_evict-1:
            if self.EC[ins_table_num][writePos]==self.eleEmptyForm:
                self.EC[ins_table_num][writePos]=kickedV
                self.TC[ins_table_num][writePos]=kickedTag
                self.posDict[0][ins_table_num][writePos]=kickedPos
                return
            else:
                tempKickedV = self.EC[ins_table_num][writePos]
                tempKickedTag = self.TC[ins_table_num][writePos]
                tempKickedPos = writePos
                tempWritePos = self.posDict[0][ins_table_num][writePos]

                self.EC[ins_table_num][writePos] = kickedV
                self.TC[ins_table_num][writePos] = kickedTag
                self.posDict[0][ins_table_num][writePos] = kickedPos # kickedPos writePos

                kickedV = tempKickedV
                kickedTag = tempKickedTag
                kickedPos = tempKickedPos
                writePos = tempWritePos

                ins_table_num = ins_table_num^1

                count += 1
        if count==self.threshold_evict-1:
            self.ES.append(kickedV)
            self.TS.append(kickedTag)

    def writeToTableETTT(self, lev,kv,shareTag,levPos0,levPos1,ellPos0,ellPos1):
        assert isinstance(shareTag, bytes)
        self.full[lev-self.ell]=1
        ins_preservedV = kv
        ins_preservedTag = shareTag
        ins_table_num = 0
        #Loc = [self.hash_one(comp_tag), self.hash_two(comp_tag)]
        kickedPos = -1
        writePos = -1
        Loc = [levPos0, levPos1]
        #kicked_V = self.emptyEleForm
        if self.ET[lev-self.ell][0][Loc[0]]==self.eleEmptyForm:
            self.ET[lev-self.ell][0][Loc[0]]=ins_preservedV
            self.TT[lev-self.ell][0][Loc[0]]=ins_preservedTag
            self.posDict[lev-self.ell][0][Loc[0]]=Loc[1]
            return
        elif self.ET[lev-self.ell][1][Loc[1]]==self.eleEmptyForm:
            self.ET[lev-self.ell][1][Loc[1]]=ins_preservedV
            self.TT[lev-self.ell][1][Loc[1]]=ins_preservedTag
            self.posDict[lev-self.ell][1][Loc[1]]=Loc[0]
            return
        else:
            ins_table_num = 0
            kickedV = self.ET[lev-self.ell][ins_table_num][Loc[ins_table_num]]
            kickedTag = self.TT[lev-self.ell][ins_table_num][Loc[ins_table_num]] # kicked
            kickedPos = Loc[ins_table_num]
            writePos = self.posDict[lev-self.ell][ins_table_num][Loc[ins_table_num]]

            self.ET[lev-self.ell][ins_table_num][Loc[ins_table_num]]=ins_preservedV
            self.TT[lev-self.ell][ins_table_num][Loc[ins_table_num]]=ins_preservedTag
            self.posDict[lev-self.ell][ins_table_num][Loc[ins_table_num]] = Loc[ins_table_num^1]
            ins_table_num = ins_table_num^1

        count = 0
        while count<self.threshold_evict-1:
            if self.ET[lev-self.ell][ins_table_num][writePos]==self.eleEmptyForm:
                self.ET[lev-self.ell][ins_table_num][writePos]=kickedV
                self.TT[lev-self.ell][ins_table_num][writePos]=kickedTag
                self.posDict[lev-self.ell][ins_table_num][writePos]=kickedPos
                return
            else:
                tempKickedV = self.ET[lev-self.ell][ins_table_num][writePos]
                tempKickedTag = self.TT[lev-self.ell][ins_table_num][writePos]
                tempKickedPos = writePos
                tempWritePos = self.posDict[lev-self.ell][ins_table_num][writePos]

                self.ET[lev-self.ell][ins_table_num][writePos] = kickedV
                self.TT[lev-self.ell][ins_table_num][writePos] = kickedTag
                self.posDict[lev-self.ell][ins_table_num][writePos] = kickedPos # kickedPos writePos

                kickedV = tempKickedV
                kickedTag = tempKickedTag
                kickedPos = tempKickedPos
                writePos = tempWritePos

                ins_table_num = ins_table_num^1

                count += 1
        if count==self.threshold_evict-1:
            self.writeToTableEll(kickedV,kickedTag,ellPos0,ellPos1)

    def oramServerInitialization(self):
        ddDlist = []
        for _ in range(self.N):
            ddDlist.append(self.receiveM())
        for dStr in ddDlist:
            k = int(dStr[:self.AddrSize])
            v = str(dStr[self.AddrSize:self.AddrSize+self.BlockSize])
            shareTag = cutils.strToBytes(dStr[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.TagSize])
            LPos0 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize:self.AddrSize+self.BlockSize+self.TagSize+self.PosInTabSize])
            LPos1 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+2*self.PosInTabSize])
            ellPos0 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+3*self.PosInTabSize])
            ellPos1 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+4*self.PosInTabSize])
            self.writeToTableETTT(self.L,(k,v),shareTag,LPos0,LPos1,ellPos0,ellPos1)
        
        self.full[self.L-self.ell]=1

    def oramServerAccess(self):
        self.tcpSoc.sendMessage("Done")
        """
        EB
        """
        if len(self.EB)>1:
            modV = cutils.strToBytes(self.receiveM())
            prgK, convertK, k_1 = cutils.strToDpfKeys(self.receiveM())
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TB),1,k_1)
            cutils.pirWriteWithEval(Bi,modV,self.TB)
        """
        ES
        """
        if len(self.ES)>1:
            modV = cutils.strToBytes(self.receiveM())
            prgK, convertK, k_1 = cutils.strToDpfKeys(self.receiveM())
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TS),1,k_1)
            cutils.pirWriteWithEval(Bi,modV,self.TS)

        """
        Read EllEC
        """ 
        tempDpfK0List = []
        tempDpfK1List = []
        if self.full[0]==1:     
            tempDpfK0List.append(self.receiveM()) #strDpfK0 =  strDpfK1 = 
            tempDpfK1List.append(self.receiveM())
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            tempDpfK0List.append(self.receiveM()) #strDpfK0 =  strDpfK1 = 
            tempDpfK1List.append(self.receiveM())
        tempEllInd = 0
        if self.full[0]==1:
            tempEllInd = 1
            strDpfK0 = tempDpfK0List[0]
            strDpfK1 = tempDpfK1List[0]
        
            prgK0, convertK0, k_00 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.EC[0]),1,k_00)
            val0 = cutils.readWithPos(Bi0,self.EC[0],self.posDict[0][0])
            
            prgK1, convertK1, k_01 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.EC[1]),1,k_01)
            val1 = cutils.readWithPos(Bi1,self.EC[1],self.posDict[0][1])

            self.tcpSoc.sendMessage(cutils.padToSize(str(val0[0]),self.AddrSize)+str(val0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(val1[0]),self.AddrSize)+str(val1[1]))
        
        tempInd = tempEllInd
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            
            strDpfK0 = tempDpfK0List[tempInd]
            strDpfK1 = tempDpfK1List[tempInd]

            prgK0, convertK0, k_00 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.ET[lev-self.ell][0]),1,k_00)
            val0 = cutils.readWithPos(Bi0,self.ET[lev-self.ell][0],self.posDict[lev-self.ell][0])
            
            prgK1, convertK1, k_01 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.ET[lev-self.ell][1]),1,k_01)
            val1 = cutils.readWithPos(Bi1,self.ET[lev-self.ell][1],self.posDict[lev-self.ell][1])

            self.tcpSoc.sendMessage(cutils.padToSize(str(val0[0]),self.AddrSize)+str(val0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(val1[0]),self.AddrSize)+str(val1[1]))
            tempInd += 1
            
        if self.full[0]==1:
            tempEllInd = 1
            """
            Write to EllTC
            """
            strModV0 = self.receiveM()
            strDpfK0 = self.receiveM()
            strModV1 = self.receiveM()
            strDpfK1 = self.receiveM()
            modV0 = cutils.strToBytes(strModV0)
            prgK, convertK, k_0 = cutils.strToDpfKeys(strDpfK0)
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TC[0]),1,k_0)
            cutils.pirWriteWithEvalAndPos(Bi,modV0,self.TC[0],self.posDict[0][0])

            modV1 = cutils.strToBytes(strModV1)
            prgK, convertK, k_0 = cutils.strToDpfKeys(strDpfK1)
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TC[1]),1,k_0)
            cutils.pirWriteWithEvalAndPos(Bi,modV1,self.TC[1],self.posDict[0][1])

        """
        ET and TT
        """
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            """
            Write to EllTC
            """
            strModV0 = self.receiveM()
            strDpfK0 = self.receiveM()
            strModV1 = self.receiveM()
            strDpfK1 = self.receiveM()


            modV0 = cutils.strToBytes(strModV0)
            prgK, convertK, k_0 = cutils.strToDpfKeys(strDpfK0)
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TT[lev-self.ell][0]),1,k_0)
            cutils.pirWriteWithEvalAndPos(Bi,modV0,self.TT[lev-self.ell][0],self.posDict[lev-self.ell][0])

            modV1 = cutils.strToBytes(strModV1)
            prgK, convertK, k_0 = cutils.strToDpfKeys(strDpfK1)
            Bi = cutils.dpfEvalAll(prgK,convertK,len(self.TT[lev-self.ell][1]),1,k_0)
            cutils.pirWriteWithEvalAndPos(Bi,modV1,self.TT[lev-self.ell][1],self.posDict[lev-self.ell][1])

        """
        Write to EB
        """
        tempMess = self.receiveM()
        kk,vv,reTag = int(tempMess[:self.AddrSize]),str(tempMess[self.AddrSize:self.AddrSize+self.BlockSize]),cutils.strToBytes(tempMess[self.AddrSize+self.BlockSize:]) 
        self.EB.append((kk,vv))
        self.TB.append(reTag)

        self.ctr += 1
        self.ellAccessTimes += 1

        if self.ctr%(2**self.L)==0:
            self.oramServerRebuildL()
        elif self.ctr%(2**(self.ell+1)) == 0:
            for j in range(self.ell+1, self.L):
                if self.full[j-self.ell]==0:
                    #print("ctr:{}".format(self.ctr))
                    #print("rebuildLevel:{}".format(j))
                    self.oramServerRebuild(j)
                    self.full[j-self.ell]=1
                    break
        elif self.ellAccessTimes % math.ceil(math.log2(self.N)) == 0:
            self.oramServerRebuildFL()

    def oramServerRebuildFL(self):
        tmpEC = copy.deepcopy(self.EC)
        self.EC = [[self.eleEmptyForm for i in range(len(tmpEC[0]))] for j in range(2)] # store (a, v, levelndex): (str, str, str)
        tmpES = copy.deepcopy(self.ES)
        self.ES = [self.eleEmptyForm]
        tmpEB = copy.deepcopy(self.EB)
        self.EB = [self.eleEmptyForm]

        tmpTC = copy.deepcopy(self.TC)
        self.TC = [[self.tagEmptyForm for i in range(len(tmpTC[0]))] for j in range(2)] # store (tag, levelIndex): (16-byte, str)
        tmpTS = copy.deepcopy(self.TS)
        self.TS = [self.tagEmptyForm]
        tmpTB = copy.deepcopy(self.TB)
        self.TB = [self.tagEmptyForm]
        
        tmpDict = copy.deepcopy(self.posDict[0])
        self.posDict[0] = [{},{}]
        if len(tmpEB)>1:
            for i in range(len(tmpEB)-1, 0, -1):
                self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTB[i])) # send tag
        if len(tmpES)>1:
            for i in range(1,len(tmpES)):
                self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTS[i]))
        for i in dict.keys(tmpDict[0]):
            self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTC[0][i]))
        for i in dict.keys(tmpDict[1]):
            self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTC[1][i])) 

        if len(tmpEB)>1:
            for i in range(len(tmpEB)-1, 0, -1):
                dataList = self.receiveM()
                k,v,ellPos0,ellPos1 = int(dataList[:self.AddrSize]),dataList[self.AddrSize:self.AddrSize+self.BlockSize],int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize]),int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:])
                self.writeToTableEll((k,v),tmpTB[i],ellPos0,ellPos1) 
        if len(tmpES)>1:
            for i in range(1,len(tmpES)):
                dataList = self.receiveM()
                k,v,ellPos0,ellPos1 = int(dataList[:self.AddrSize]),dataList[self.AddrSize:self.AddrSize+self.BlockSize],int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize]),int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:])
                self.writeToTableEll((k,v),tmpTS[i],ellPos0,ellPos1)
        for i in dict.keys(tmpDict[0]):
            dataList = self.receiveM()
            k,v,ellPos0,ellPos1 = int(dataList[:self.AddrSize]),dataList[self.AddrSize:self.AddrSize+self.BlockSize],int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize]),int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:])
            self.writeToTableEll((k,v),tmpTC[0][i],ellPos0,ellPos1) 
        for i in dict.keys(tmpDict[1]):
            dataList = self.receiveM()
            k,v,ellPos0,ellPos1 = int(dataList[:self.AddrSize]),dataList[self.AddrSize:self.AddrSize+self.BlockSize],int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize]),int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:])
            self.writeToTableEll((k,v),tmpTC[1][i],ellPos0,ellPos1) 

        self.full[0] = 1
        self.ellAccessTimes = 0

    def oramServerRebuild(self, lev):
        tmpEC = copy.deepcopy(self.EC)
        self.EC = [[self.eleEmptyForm for i in range(len(tmpEC[0]))] for j in range(2)] # store (a, v, levelndex): (str, str, str)
        tmpES = copy.deepcopy(self.ES)
        self.ES = [self.eleEmptyForm]
        tmpEB = copy.deepcopy(self.EB)
        self.EB = [self.eleEmptyForm]

        tmpTC = copy.deepcopy(self.TC)
        self.TC = [[self.tagEmptyForm for i in range(len(tmpTC[0]))] for j in range(2)] # store (tag, levelIndex): (16-byte, str)
        tmpTS = copy.deepcopy(self.TS)
        self.TS = [self.tagEmptyForm]
        tmpTB = copy.deepcopy(self.TB)
        self.TB = [self.tagEmptyForm]

        tmpEllDict = copy.deepcopy(self.posDict[0])
        self.posDict[0] = [{},{}]
        self.full[0] = 0

        if len(tmpEB)>1:
            for i in range(len(tmpEB)-1, 0, -1):
                self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTB[i]))
        if len(tmpES)>1:
            for i in range(1,len(tmpES)):
                self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTS[i]))
        for i in dict.keys(tmpEllDict[0]):
            self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTC[0][i]))
        for i in dict.keys(tmpEllDict[1]):
            self.tcpSoc.sendMessage(cutils.bytesToStr(tmpTC[1][i]))
        for j in range(self.ell+1,lev):
            for i in dict.keys(self.posDict[j-self.ell][0]):
                self.tcpSoc.sendMessage(cutils.bytesToStr(self.TT[j-self.ell][0][i])) 
            for i in dict.keys(self.posDict[j-self.ell][1]):
                self.tcpSoc.sendMessage(cutils.bytesToStr(self.TT[j-self.ell][1][i]))

        if len(tmpEB)>1:
            for i in range(len(tmpEB)-1, 0, -1):
                dataList = self.receiveM()
                k = int(dataList[:self.AddrSize])
                v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
                levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
                levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
                ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
                ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
                self.writeToTableETTT(lev,(k,v),tmpTB[i],levPos0,levPos1,ellPos0,ellPos1)
        if len(tmpES)>1:
            for i in range(1,len(tmpES)):
                dataList = self.receiveM()
                k = int(dataList[:self.AddrSize])
                v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
                levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
                levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
                ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
                ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
                self.writeToTableETTT(lev,(k,v),tmpTS[i],levPos0,levPos1,ellPos0,ellPos1)
        for i in dict.keys(tmpEllDict[0]):
            dataList = self.receiveM()
            k = int(dataList[:self.AddrSize])
            v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
            levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
            levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
            ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
            ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
            self.writeToTableETTT(lev,(k,v),tmpTC[0][i],levPos0,levPos1,ellPos0,ellPos1)
        for i in dict.keys(tmpEllDict[1]):
            dataList = self.receiveM()
            k = int(dataList[:self.AddrSize])
            v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
            levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
            levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
            ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
            ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
            self.writeToTableETTT(lev,(k,v),tmpTC[1][i],levPos0,levPos1,ellPos0,ellPos1)
        for j in range(self.ell+1,lev):
            for i in dict.keys(self.posDict[j-self.ell][0]):
                dataList = self.receiveM()
                k = int(dataList[:self.AddrSize])
                v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
                levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
                levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
                ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
                ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
                self.writeToTableETTT(lev,(k,v),self.TT[j-self.ell][0][i],levPos0,levPos1,ellPos0,ellPos1) 
            for i in dict.keys(self.posDict[j-self.ell][1]):
                dataList = self.receiveM()
                k = int(dataList[:self.AddrSize])
                v = str(dataList[self.AddrSize:self.AddrSize+self.BlockSize])
                levPos0 = int(dataList[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.PosInTabSize])
                levPos1 = int(dataList[self.AddrSize+self.BlockSize+self.PosInTabSize:self.AddrSize+self.BlockSize+2*self.PosInTabSize])
                ellPos0 = int(dataList[self.AddrSize+self.BlockSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+3*self.PosInTabSize])
                ellPos1 = int(dataList[self.AddrSize+self.BlockSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+4*self.PosInTabSize])
                self.writeToTableETTT(lev,(k,v),self.TT[j-self.ell][1][i],levPos0,levPos1,ellPos0,ellPos1) 
            
            self.full[j-self.ell] = 0
            self.posDict[j-self.ell] = [{},{}]
            temp_length = (int)((1+self.cuckooEpsilon)*(2**j))
            self.ET[j-self.ell] = [[self.eleEmptyForm for i in range(temp_length)],[self.eleEmptyForm for i in range(temp_length)]]
            self.TT[j-self.ell] = [[self.tagEmptyForm for i in range(temp_length)],[self.tagEmptyForm for i in range(temp_length)]]
        
        self.full[lev-self.ell] = 1
        self.ellAccessTimes = 0

    def oramServerRebuildL(self):
        ddDlist = []
        for _ in range(self.N):
            self.oramServerAccessOnlyRead()
            ddDlist.append(self.receiveM())

        self.EC = [[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*self.ecEllLength))] for j in range(2)] # store (a, v, levelndex): (str, str, str)
        self.ES = [self.eleEmptyForm]
        self.EB = [self.eleEmptyForm]

        self.TC = [[self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*self.ecEllLength))] for j in range(2)] # store (tag, levelIndex): (16-byte, str)
        self.TS = [self.tagEmptyForm]
        self.TB = [self.tagEmptyForm]


        self.ET = [[[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))],[self.eleEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))]] for j in range(self.L-self.ell+1)]
        self.TT = [[[self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))], [self.tagEmptyForm for i in range((int)((1+self.cuckooEpsilon)*(2**(j+self.ell))))]] for j in range(self.L-self.ell+1)]
        
        self.posDict = [[{},{}] for _ in range(self.L-self.ell+1)]

        self.full = [0 for i in range(self.L-self.ell+1)]

        for dStr in ddDlist:
            k = int(dStr[:self.AddrSize])
            v = str(dStr[self.AddrSize:self.AddrSize+self.BlockSize])
            shareTag = cutils.strToBytes(dStr[self.AddrSize+self.BlockSize:self.AddrSize+self.BlockSize+self.TagSize])
            LPos0 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize:self.AddrSize+self.BlockSize+self.TagSize+self.PosInTabSize])
            LPos1 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+2*self.PosInTabSize])
            ellPos0 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+2*self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+3*self.PosInTabSize])
            ellPos1 = int(dStr[self.AddrSize+self.BlockSize+self.TagSize+3*self.PosInTabSize:self.AddrSize+self.BlockSize+self.TagSize+4*self.PosInTabSize])
            self.writeToTableETTT(self.L,(k,v),shareTag,LPos0,LPos1,ellPos0,ellPos1)
        
        self.full[self.L-self.ell]=1
        self.ellAccessTimes = 0

    def oramServerAccessOnlyRead(self):
        """
        Read EllEC
        """ 
        tempDpfK0List = []
        tempDpfK1List = []
        if self.full[0]==1:       
            tempDpfK0List.append(self.receiveM())
            tempDpfK1List.append(self.receiveM())
        for lev in range(self.ell+1,self.L+1):
            tempDpfK0List.append(self.receiveM())
            tempDpfK1List.append(self.receiveM())

        if self.full[0]==1:    
            strDpfK0 = tempDpfK0List[0]
            strDpfK1 = tempDpfK1List[0]

            prgK0, convertK0, k_00 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.EC[0]),1,k_00)
            val0 = cutils.readWithPos(Bi0,self.EC[0],self.posDict[0][0])
            
            prgK1, convertK1, k_01 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.EC[1]),1,k_01)
            val1 = cutils.readWithPos(Bi1,self.EC[1],self.posDict[0][1])

            self.tcpSoc.sendMessage(cutils.padToSize(str(val0[0]),self.AddrSize)+str(val0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(val1[0]),self.AddrSize)+str(val1[1]))
        
        """
        ET and TT
        """
        for lev in range(self.ell+1,self.L+1):
            assert self.full[lev-self.ell]==1       
            
            strDpfK0 = tempDpfK0List[lev-self.ell]
            strDpfK1 = tempDpfK1List[lev-self.ell]
            
            prgK0, convertK0, k_00 = cutils.strToDpfKeys(strDpfK0)
            Bi0 = cutils.dpfEvalAll(prgK0,convertK0,len(self.ET[lev-self.ell][0]),1,k_00)
            val0 = cutils.readWithPos(Bi0,self.ET[lev-self.ell][0],self.posDict[lev-self.ell][0])
            
            
            prgK1, convertK1, k_01 = cutils.strToDpfKeys(strDpfK1)
            Bi1 = cutils.dpfEvalAll(prgK1,convertK1,len(self.ET[lev-self.ell][1]),1,k_01)
            val1 = cutils.readWithPos(Bi1,self.ET[lev-self.ell][1],self.posDict[lev-self.ell][1])
            self.tcpSoc.sendMessage(cutils.padToSize(str(val0[0]),self.AddrSize)+str(val0[1]))
            self.tcpSoc.sendMessage(cutils.padToSize(str(val1[0]),self.AddrSize)+str(val1[1]))
        
if __name__=="__main__":
    soram = ORAMServer()
    soram.oramServerInitialization()
    access_times = soram.access_times#(int)(2*math.log2(soram.N))#513#4*soram.N-1
    bb = time.time()
    for i in range(access_times):
        retrievedEle = soram.oramServerAccess()

    soram.tcpSoc.closeConnection()