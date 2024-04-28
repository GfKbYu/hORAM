import socket
from socket import *
import time
import struct
"""
Two servers:
Aliyun: 8.130.121.76
TencentCloud: 43.143.163.4
"""
Addr0 = "43.143.209.19"
Port0 = 4000
Addr1 = "101.42.30.218"
Port1 = 4000

class tcpClient:

    def __init__(self, ipAddr, ipPort, byteOfComm): 
        self.CurrentState = "Init" # Init, Send, Receive
        self.Bandwidth = 0
        self.Rounds = 0
        self.client_socket = socket(AF_INET,SOCK_STREAM)
        self.client_socket.connect((ipAddr, ipPort))
        self.byteOfComm = byteOfComm
        # 查看默认发送接收缓冲区大小

    def sendMessage(self, message):
        self.client_socket.sendall(struct.pack('i',len(str(message))))
        self.client_socket.sendall(str(message).encode("ISO-8859-1")) #.ljust(self.byteOfComm)

        """
        Overhead
        """
        self.Bandwidth += len(str(message))
        if self.CurrentState!='Send':
            self.Rounds += 1
            self.CurrentState = 'Send'
        
        return

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
        """
        Overhead
        """
        self.Bandwidth += len(from_server_msg)
        if self.CurrentState!='Receive':
            self.Rounds += 1
            self.CurrentState = 'Receive'

        return from_server_msg.decode("ISO-8859-1")

    def closeConnection(self):
        self.client_socket.close()
    
if __name__=="__main__":
    tclient = tcpClient(Addr0,Port0,1024)
    
    NN = 2**8
    LL = []
    for i in range(NN):
        LL.append(str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1))
    for i in range(len(LL)):
        print(LL[i])
        tclient.sendMessage(LL[i])
    #tclient.sendMessage("Done")
    #print(tclient.receiveMessage().split( ))
    tclient.closeConnection() 
    #print(LL)
    

"""

    udpC = udpClient()
    klkl = ["3142rnfewng","wr","qeqrwr"]
    for i in range(3):
        udpC.sendMessage(klkl[i],Addr0,Port0)
    #udpC.closeSocket()


def __init__(self) -> None:
        self.sock = socket(AF_INET, SOCK_DGRAM)
    
    def sendMessage(self, message, addr, port): # message: str
        #print(message.encode('utf-8'),)
        self.sock.sendto(message.encode('utf-8'), (addr, port))

    def receiveMessage(self, byteOfCom):
        recvData = self.sock.recvfrom(byteOfCom)
        return recvData[0].decode('utf-8'),recvData[1]

    def closeSocket(self):
        self.sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('localhost', 10000))
while False:
    data, address = sock.recvfrom(4096)
    print(data.decode('UTF-8'), address)
    if data:
        sent = sock.sendto('已接收到你发来的消息'.encode('UTF-8'), address)

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    msg = "发送消息到服务器".encode('utf-8')
    sent = sock.sendto(msg, ('localhost', 10000))
    data, server = sock.recvfrom(4096)
    print(data.decode())
finally:
    sock.close()

    
def createConnection(ipAddr, ipPort): 
    tcp_socket = socket(AF_INET,SOCK_STREAM)
    tcp_socket.connect((ipAddr, ipPort))
    return tcp_socket

def sendMessage(tcp_socket, message):
    tcp_socket.send(message.encode("utf-8"))
    #tcp_socket.send(message) # json.dumps(message).encode()

def receiveMessage(tcp_socket, byteOfComm):
    #myList = json.loads(received_bytes.decode())
    from_server_msg = tcp_socket.recv(byteOfComm)
    #加上.decode("gbk")可以解决乱码
    return from_server_msg

def closeConnection(tcp_socket):
    tcp_socket.close()



if __name__=="__main__":
    #sendM2 = (("dwew","eqq","qq"), ("1","8"))
    #print(bytes(json.dumps(sendM2).encode('utf-8')))
    tcp_socket_1 = createConnection(Addr1, Port1)
    #tcp_socket_2 = createConnection(Addr2, Port2)

    #myList = [99,88,{'a': 3},77]
    #current_connection.send(json.dumps(myList).encode())

    #myList = json.loads(received_bytes.decode())


    sendM1 = (("dwew","eqq","qq"), (1, 2), (3, 4))#, (("rw","ds","d"), 11, 22, 33, 44)]
    #print(json.dumps(sendM1).encode())
    sendM2 = ["dwew","eqq","qq"]
    #for i in range(len(sendM2)):
    sendMessage(tcp_socket_1, sendM1)
        #sendMessage(tcp_socket_2, sendM2[i])
    
    closeConnection(tcp_socket_1)
    #closeConnection(tcp_socket_2)
     
"""