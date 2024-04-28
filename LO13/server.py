#Authors:xiaobei

######客户端创建######

import socket
from socket import *
import time
import struct
#创建一个socket
class tcpServer2:
    def __init__(self,byteOfComm):
        self.byteOfComm = byteOfComm
        self.tcp_server = socket(AF_INET,SOCK_STREAM)
        self.tcp_server.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
        self.tcp_server.bind(('',4000))
        self.tcp_server.listen(1)
        self.client_socket, _ = self.tcp_server.accept()

        

        self.sendTime = 0 
        self.recTime1 = 0 
        self.recTime2 = 0

    def sendMessage(self, message):
        bTime = time.time()
        self.client_socket.sendall(struct.pack('i',len(str(message))))
        self.client_socket.sendall(str(message).encode("ISO-8859-1")) #.ljust(self.byteOfComm)

        self.sendTime += time.time()-bTime

    def receiveMessage(self):
        
        bTime = time.time()

        int_length = 4
        dataL = b''
        while len(dataL) < int_length: #循环接收数据
            dataL += self.client_socket.recv(int_length - len(dataL))
        e0Time = time.time()
        self.recTime1 += e0Time-bTime
        data_length = struct.unpack('i',dataL)[0]
        from_server_msg = b''
        while data_length>0:
            if data_length>self.byteOfComm:
                temp = self.client_socket.recv(self.byteOfComm)
            else:
                temp = self.client_socket.recv(data_length)
        #while len(from_server_msg) < data_length: #循环接收数据
            from_server_msg += temp
            data_length -= len(temp)
        #print(len(from_server_msg))
        self.recTime2 += time.time()-e0Time
        return from_server_msg.decode("ISO-8859-1")
        

    def closeConnection(self):
        self.tcp_server.close()
        self.client_socket.close()


class tcpServer:
    def __init__(self,byteOfComm):
        self.byteOfComm = byteOfComm
        self.tcp_server = socket(AF_INET,SOCK_STREAM)
        self.tcp_server.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
        self.tcp_server.bind(('',4000))
        self.tcp_server.listen(1)
        self.client_socket, _ = self.tcp_server.accept()

    def sendMessage(self, message):
        self.client_socket.sendall(struct.pack('i',len(str(message))))
        self.client_socket.sendall(str(message).encode("ISO-8859-1")) #.ljust(self.byteOfComm)

    def receiveMessage(self):
        int_length = 4
        dataL = b''
        while len(dataL) < int_length: #循环接收数据
            dataL += self.client_socket.recv(int_length - len(dataL))
        data_length = struct.unpack('i',dataL)[0]
        from_server_msg = b''
        while data_length>0:
            if data_length>self.byteOfComm:
                temp = self.client_socket.recv(self.byteOfComm)
            else:
                temp = self.client_socket.recv(data_length)
        #while len(from_server_msg) < data_length: #循环接收数据
            from_server_msg += temp
            data_length -= len(temp)
        #print(len(from_server_msg))
        return from_server_msg.decode("ISO-8859-1")
        

    def closeConnection(self):
        self.tcp_server.close()
        self.client_socket.close()

if __name__=="__main__":
    
    str_list = ['0' for i in range(2)]
    sc = ''.join(str_list)
    udpS = tcpServer2(2**15)
    LL = []
    for i in range(20):
        udpS.sendMessage(sc)
        udpS.receiveMessage()
    udpS.closeConnection() 
    
    print(udpS.sendTime,udpS.recTime1,udpS.recTime2)
