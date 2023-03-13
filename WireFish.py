import threading
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import os
import csv
from scapy.all import *


class PacketPage:
    def __init__(self, title, packet, time, num, length, prot):
        self.AllText = []
        master = Tk()
        master.geometry("1000x600")
        master.title(str(num) + "    " +str(title))
        scrollbar = Scrollbar(master)
        scrollbar.pack(side=RIGHT, fill="y")

        ###FRAME###
        self.AllText.append("-----FRAME-----")
        PktArivalTime = "Arival Time: " + str(self.TimeInWords(time))
        PktNum ="Frame Number: "+  str(num)
        FrameLength = "Frame Length: " + str(length)+ " (" + str(int(length)*8) + " bits)" #full length of packet, frame len  = len of everything
        EnCapType = "Encapsulation Type: Ethernet"
        self.AllText.append(EnCapType)
        self.AllText.append(PktArivalTime)
        self.AllText.append(PktNum)
        self.AllText.append(FrameLength)
        self.AllText.append(" ")
        #protocols in frame (eth:ethertyre always or ethernet)

        ###ETHERNET###
        self.AllText.append("-----ETHERNET-----")
        EthDst = "Destination: " + packet[Ether].dst
        EthSrc = "Source: " + packet[Ether].src
        IpType = "Type: " + self.IPType(packet,prot)
        self.AllText.append(EthDst)
        self.AllText.append(EthSrc)
        self.AllText.append(IpType)
        if Padding in packet:
            PaddingList = map(ord, packet[Padding].load) # \x00\x00 to dec
            padding = ''.join(str(i) for i in PaddingList)
            self.AllText.append(padding)
        self.AllText.append(" ")

        ###IP###
        if IP in packet:
            self.AllText.append("----- IP (Internet Prototcol) -----")
            Version = "Version: " + str(self.IpVersion(packet,IpType))
            #HeaderLen = "Header Length: " +str(packet)[:(packet[IP].ihl * 4)]
            HeaderLen = "Header Length: 20" # ip header len always 20 ?
            TotalLen = "Total Length: " + str(packet[IP].len) #includes len of tcp / udp ?
            TimeToLive = "Time To Live: " + str(packet[IP].ttl)
            Prot = "Protocol: " + prot
            IpSrc = "Source: " + str(packet[IP].src)
            IpDst = "Destination: " + str(packet[IP].dst)
            self.AllText.append(Version)
            self.AllText.append(HeaderLen)
            self.AllText.append(TotalLen)
            self.AllText.append(Prot)
            self.AllText.append(TimeToLive)
            self.AllText.append(IpSrc)
            self.AllText.append(IpDst)
            #total len = ip header len + udp/tcp len, rest is frame len - total len (dns,http..) ip header len always 20
            #Flags: 000/001/010. 000 - not set in all(reserved bit, dont fragemnet, more fragments), 001 : more fragements : set, 010: dont fragment - set)
            #fragemnet offset: frag value in show()
            Flags = "Flags: "+ str(packet[IP].flags)
            self.AllText.append(Flags)
            ReservedBit = None
            DontFragment = None
            MoreFragments = None
            if packet[IP].flags == 0: #000
                ReservedBit = "    . . . . Reserved bit: Not set"
                DontFragment = "    . . . . Don't fragment: Not set"
                MoreFragments = "    . . . . More fragments: Not set"
            if packet[IP].flags == 1: #001
                ReservedBit = ". . . . Reserved bit: Not set"
                DontFragment = ". . . . Don't fragment: Not set"
                MoreFragments = ". . . . More fragments: Set"
            if packet[IP].flags == 2: #010
                ReservedBit = ". . . . Reserved bit: Not set"
                DontFragment = ". . . . Don't fragment: Set"
                MoreFragments = ". . . . More fragments: Not set"

            self.AllText.append(ReservedBit)
            self.AllText.append(DontFragment)
            self.AllText.append(MoreFragments)
            self.AllText.append(" ")

            ###ICMP###
            if ICMP in packet:
                self.AllText.append("----- ICMP (Internet Control Message Prototcol) -----")
                icmpType = "Type: " + self.IcmpType(packet)
                icmpCode = "Code: " + str(self.IcmpCode(packet))
                icmpCheckSum = "Checksum: " + str(packet[ICMP].chksum)
                icmpIp = "Identifier: " + str(packet[ICMP].id)
                icmpSeq = "Sequence number: " + str(packet[ICMP].seq)
                self.AllText.append(icmpType)
                self.AllText.append(icmpCode)
                self.AllText.append(icmpCheckSum)
                self.AllText.append(icmpIp)
                self.AllText.append(icmpSeq)
                self.AllText.append("----- Data -----")
                icmpData = "Data: " + str(packet[Raw].load.encode("hex"))
                icmpDataLen = "[Length: " + str(len(packet[Raw].load)) + "]"
                self.AllText.append(" ")
                self.AllText.append(icmpData)
                self.AllText.append(icmpDataLen)


            ###UDP###
            elif UDP in packet:
                self.AllText.append("----- UDP (User Datagram Protocol) -----")
                SrcPort = "Source Port: " + str(packet[UDP].sport)
                DstPort = "Destination Port: "+ str(packet[UDP].dport)
                udpLen = "Length: " + str(packet[IP].len - 20) # udpLen + 20(IpHeaderLen) = IpTotalLen
                CheckSum = "Checksum: " + str(hex(packet[UDP].chksum))
                self.AllText.append(SrcPort)
                self.AllText.append(DstPort)
                self.AllText.append(udpLen)
                self.AllText.append(CheckSum)
                self.AllText.append(" ")

            ###DNS###
                if DNS in packet:
                    self.AllText.append("----- DNS (Domain Name System) -----")
                    Identication = "Transaction Identication: "+ str(len(hex(packet[DNS].id)))
                    self.AllText.append(Identication)
                    self.AllText.append("Flags-")
                    QorR = self.QueryOrResponse(packet)
                    OpCode = self.OpCode(packet)
                    Authorative = self.AuthenticatedData(packet)
                    Truncated = self.Truncated(packet)
                    RD = self.RecursionDesrired(packet)
                    RA = self.RecursionAvailable(packet)
                    RC = self.ReplyCOde(packet)
                    # missing info?
                    TotalQ = "Questions " + str(self.TotalQuestions(packet)) #Number of entries in the question list that were returned
                    TotalA_RR = "Answer RRs " + str(self.TotalAnswersRR(packet)) # Number of entries in the answer resource record list that were returned
                    TotalAth_RR = "Authority RRs: " + str(self.TotalAuthorityRR(packet)) # Number of entries in the authority resource record list that were returned
                    TotalAdd_RR = "Additional RRs: " + str(self.TotalAdditionalRR(packet)) # Number of entries in the additional resource record list that were returned

                    self.AllText.append(QorR)
                    self.AllText.append(OpCode)
                    self.AllText.append(Authorative)
                    self.AllText.append(Truncated)
                    self.AllText.append(RD)
                    self.AllText.append(RA)
                    self.AllText.append(RC)
                    self.AllText.append(TotalQ)
                    self.AllText.append(TotalA_RR)
                    self.AllText.append(TotalAth_RR)
                    self.AllText.append(TotalAdd_RR)
                    self.AllText.append(" ")

                    if self.TotalQuestions(packet) >0:
                        self.AllText.append("       ---Queries---")# DNS Question Record
                        for x in range(self.TotalQuestions(packet)): #Questions
                            self.AllText.append("  " + str(x+1) + ":")
                            dnsqrName ="  Name: "+ packet[DNSQR][x].qname
                            dnsqrType= "  Type: " + str(self.DnsqrQtype(packet,x))
                            dnsqrClass="  Class: 0"+ str(self.DnsqrQClass(packet,x))
                            self.AllText.append(dnsqrName)
                            self.AllText.append(dnsqrType)
                            self.AllText.append(dnsqrClass)


                    if self.TotalAnswersRR(packet) >0:
                        self.AllText.append("       ---Answers---")
                        for x in range(self.TotalAnswersRR(packet)):
                            self.AllText.append("  " + str(x+1) + ":")
                            dnsrrName ="  Name: "+ packet[DNSRR][x].rrname
                            dnsrrType= "  Type: " + str(self.DnsrrQtype(packet,x))
                            dnsrrClass="  Class: 0"+ str(self.DnsrrQClass(packet,x))
                            self.AllText.append(dnsrrName)
                            self.AllText.append(dnsrrType)
                            self.AllText.append(dnsrrClass)

                    if self.TotalAuthorityRR(packet) >0:
                        try:
                            self.AllText.append("       ---Additional RRs---")
                            for x in range(self.TotalAuthorityRR(packet)):
                                self.AllText.append("  " + str(x+1) + ":")
                                dnsAuthName = "  Name: " + str(packet[DNSRR][x + self.TotalAnswersRR(packet)].rrname) ### +1, [x + self.TotalAnswersRR(packet) + 1] ?
                                dnsAuthType= "  Type: " + str(self.DnsAuthType(packet,x+ self.TotalAnswersRR(packet)))
                                dnsAuthClass="  Class: 0"+ str(self.DnsAuthRClass(packet,x+ self.TotalAnswersRR(packet)))
                                dnsAuthTtl = "  Time to live: "+ str(packet[DNSRR][x + self.TotalAnswersRR(packet) + 1].ttl)
                                DataLen = "Data Length: " + str(packet[DNSRR][x + self.TotalAnswersRR(packet) + 1].rdlen)
                                ## data ???????????
                                self.AllText.append(dnsAuthName)
                                self.AllText.append(dnsAuthType)
                                self.AllText.append(dnsAuthClass)
                                self.AllText.append(dnsAuthTtl)
                                self.AllText.append(DataLen)
                        except:
                            pass



            ###TCP###
            elif TCP in packet:
                self.AllText.append("----- TCP (Transmission Control Protocol) -----")
                SrcPort = "Source port: " + str((packet[TCP].sport))
                DstPort = "Destination port: " + str(packet[TCP].dport)
                SeqNum = "Sequence number: " + str(packet[TCP].seq)
                HeaderLen = "Header Length: " + str(packet[TCP].dataofs * 4) ## tchpHeaderLen = IpTotalLen - IpHeaderLen
                WindowSIze = "Window size: " + str(packet[TCP].window)
                tcpChkSum = "Checksum: " + str(hex(packet[TCP].chksum))
                Flags = "Flags: "+ self.TcpFlags(packet)
                self.AllText.append(SrcPort)
                self.AllText.append(DstPort)
                self.AllText.append(SeqNum)
                self.AllText.append(HeaderLen)
                self.AllText.append(WindowSIze)
                self.AllText.append(tcpChkSum)
                self.AllText.append(Flags)
                self.AllText.append(" ")

                ###HTTP###
                if Raw in packet:
                    #GET#
                    if str(packet[Raw]).startswith('GET'):
                        self.AllText.append("----- HTTP GET REQUEST-----")
                        splitLoad = packet[Raw].load.split("\r\n") #raw data split into lines
                        HttpReqMethod ="Request Method: " +  splitLoad[0].split(" ")[0]
                        HttpReqVersion = "Request Version: " + splitLoad[0].split(" ")[-1]
                        HttpHost = "Host: " + splitLoad[1].split(" ")[1]
                        HttpConnection = splitLoad[2]
                        HttpUserAgent = splitLoad[3]
                        HttpAccept = splitLoad[3]
                        HttpReferer = splitLoad[4]
                        HttpAccEncoding = splitLoad[5]
                        HttpAccLanguage = splitLoad[6]
                        self.AllText.append(HttpReqMethod)
                        self.AllText.append(HttpReqVersion)
                        self.AllText.append(HttpHost)
                        self.AllText.append(HttpConnection)
                        self.AllText.append(HttpUserAgent)
                        self.AllText.append(HttpAccept)
                        self.AllText.append(HttpReferer)
                        self.AllText.append(HttpAccEncoding)
                        self.AllText.append(HttpAccLanguage)
                        self.AllText.append(" ")

                    #POST#
                    if str(packet[Raw]).startswith('POST'):
                        self.AllText.append("-- HTTP POST REQUEST --")
                        splitLoad = packet[Raw].load.split("\r\n") #raw data split into lines
                        HttpReqMethod ="Request Method: " +  splitLoad[0].split(" ")[0]
                        HttpReqVersion = "Request Version: " + splitLoad[0].split(" ")[-1]
                        HttpHost = "Host: " + splitLoad[1].split(" ")[1]
                        HttpConnection = splitLoad[2]
                        HttpContentLen = splitLoad[3]
                        HttpOrigin = splitLoad[4]
                        HttpUserAgent = splitLoad[5]
                        HttpContentType = splitLoad[6]
                        HttpAccept = splitLoad[7]
                        HttpReferer = splitLoad[8]
                        HttpAccEncoding = splitLoad[9]
                        HttpAccLanguage = splitLoad[10]
                        self.AllText.append(HttpReqMethod)
                        self.AllText.append(HttpReqVersion)
                        self.AllText.append(HttpHost)
                        self.AllText.append(HttpConnection)
                        self.AllText.append(HttpContentLen)
                        self.AllText.append(HttpOrigin)
                        self.AllText.append(HttpUserAgent)
                        self.AllText.append(HttpContentType)
                        self.AllText.append(HttpAccept)
                        self.AllText.append(HttpReferer)
                        self.AllText.append(HttpAccEncoding)
                        self.AllText.append(HttpAccLanguage)
                        self.AllText.append(" ")

                    #REPLY#
                    if str(packet[Raw]).startswith('HTTP'):
                        self.AllText.append("-- HTTP RESPONSE --")
                        splitLoad = packet[Raw].load.split("\r\n") #raw data split into lines
                        HttpReqVersion = "Request Version: " + splitLoad[0].split(" ")[0]
                        HttpStatusCode = "Status Code: " + splitLoad[0].split(" ")[1]
                        HttpResponsePhrase = "Response Phrase: " + splitLoad[0].split(" ")[2]
                        self.AllText.append(HttpReqVersion)
                        self.AllText.append(HttpStatusCode)
                        self.AllText.append(HttpResponsePhrase)
                        for x in range(3,len(splitLoad)-1):
                            self.AllText.append(splitLoad[x])
                        self.AllText.append(" ")

            ###SSDP###
            #in UDP or TCP?
            if (TCP in packet or UDP in packet) and Raw in packet and str(packet[Raw]).find("ssdp:discover") != 1 :
                self.AllText.append("----- SSDP (Simple Service Discovery Protocol) -----")
                if str(packet[Raw]).find("M-SEARCH * HTTP/1.1") != 1: #serach request broadcast method
                    ReqMethod = "Request method: M-SEARCH"
                    self.AllText.append(ReqMethod)
                if str(packet[Raw]).find("HTTP/1.1") != 1:
                    ReqVersion = "Request version: HTTP/1.1"
                    self.AllText.append(ReqVersion)
                ssdpHost = "Host: 239.255.255.250:1900" # all SSDP requests are sent to this host on default port 1900
                ssdpMan = "MAN: 'ssdp:discover'" #always set to this in ssdp
                self.AllText.append(ssdpHost)
                self.AllText.append(ssdpMan)
                self.AllText.append(" ")

        ###ARP###
        elif ((not(IP in packet)) and (Ether in packet)): # if ARP in packet
            self.AllText.append("----- ARP (Address Resolution Protocol) -----")
            HwType = "Hardware type: " + self.ArpHwType(packet)
            ProType = "Protocol Type" + str(self.ArpProType(packet))
            HwSize = "Hardware size: " + str(packet[ARP].hwlen)
            ProtSize = "Protocl size: " + str(packet[ARP].plen)
            ArpOpCode = "Op Code: " + self.ArpOpCode(packet)
            SenderMacAdd = "Sender MAC address: " + packet[ARP].hwsrc
            SenderIpAdd = "Sender IP address: " + packet[ARP].psrc
            TargetMacAdd = "Target MAC address: " + packet[ARP].hwdst
            TargetIpAdd = "Target IP address: " + packet[ARP].pdst
            self.AllText.append(HwType)
            self.AllText.append(ProType)
            self.AllText.append(HwSize)
            self.AllText.append(ProtSize)
            self.AllText.append(ArpOpCode)
            self.AllText.append(SenderMacAdd)
            self.AllText.append(SenderMacAdd)
            self.AllText.append(SenderIpAdd)
            self.AllText.append(TargetMacAdd)
            self.AllText.append(TargetIpAdd)
            self.AllText.append(" ")

        #print text in AllText to window
        listbox = Listbox(master, width=1000, height=100, yscrollcommand=scrollbar.set,font = "System")
        for i in range(len(self.AllText)): #number of lines in packet.show()    for i in range(text.count('\n'))
            listbox.insert(END, self.AllText[i]) #str(splitText[i])
        listbox.pack(side=LEFT, fill="both")

    def TimeInWords(self,time):
        SplitTime1 = time.split(" ")
        time1 = SplitTime1[-1] #time when packet was recieved
        SplitTime2 = str(SplitTime1).split("-")
        year = SplitTime2[0]
        month = SplitTime2[1]
        day = SplitTime2[2]
        months = ["January","February","March","Apri","May","June","July","August","September","October","November","December"]
        if month.find("0") >-1:
            month = month[1]

        monthInWords = months[int(month)-1]
        DateInWords = monthInWords + " " + day.split("'")[0] + ", " + year[2::]
        Newtime = DateInWords + " " + SplitTime1[-1]
        return Newtime

    def IPType(self,packet,prot):

        if prot == "ARP":
            return "ARP (0x0806)"

        ip = packet[IP].dst

        if ip.find(":") != -1:
            return "IPv6 (0x86dd)"  # Internet Protocol version 6
        elif ip.find(".") != -1:
            return "IPv4 (0x0800)"  # Internet Protocol version 4

    def IpVersion(self,packet,IpType):
        if IpType == "Type: IPv4 (0x0800)":
            ipVersion = 4
        if IpType == "Type: IPv6 (0x0800)":
            ipVersion = 6
        #ARP doesnt have IpVersion because it does not have IP layer
        return ipVersion

    def QueryOrResponse(self,packet):
        if packet[DNS].qr == 0:
            return ". . . . Response: Message is a query"
        if packet[DNS].qr == 1:
            return ". . . . Response: Message is a response"

    def OpCode(self,packet):
        if packet[DNS].opcode == 0:
            return ". . . . Opcode: Standard Query (0)"
        if packet[DNS].opcode == 1:
            return ". . . . Opcode: Inverse Query (1)"
        if packet[DNS].opcode == 2:
            return ". . . . Opcode: Server Status Request (2)"
        if packet[DNS].opcode == 4:
            return ". . . . Opcode: Notify (4)"
        if packet[DNS].opcode == 5:
            return ". . . . Opcode: Update  (5)"

    def AuthorativeAnswer(self,packet):
        if self.QueryOrResponse(packet) == ". . . . Response: Message is a response": # only if message if query:
            if packet[DNS].aa == 0:
                 return ". . . . Authoritative: Server is not authoritative for domain"
            if packet[DNS].aa == 1:
                 return ". . . . Authoritative: Server is authoritative for domain"

    def Truncated(self,packet): # "truncated" = only the 512 first bytes of the reply were returned
        if packet[DNS].tc == 0:
             return ". . . . Truncated: Message is not truncated"
        if packet[DNS].tc == 1:
             return ". . . . Truncated: Message not truncated"

    def RecursionDesrired(self,packet):
        if packet[DNS].rd == 0:
             return ". . . . Recursion Desired: Do query recursively"
        if packet[DNS].rd == 1:
             return ". . . . Recursion Desired: Do not do query recursively"

    def RecursionAvailable(self,packet): # indicated if recursive query support is available
        if self.QueryOrResponse(packet) == ". . . . Response: Message is a response": # only if message if query:
            if packet[DNS].ra == 0:
                 return ". . . . Recursion available: Server can do recursive queries"
            if packet[DNS].ra == 1:
                 return ". . . . Recursion available: Server can not do recursive queries"

    def AuthenticatedData(self,packet):
        if packet[DNS].rd == 0:
             return ". . . . Answer authenticated: Answer/authority portion was not authenticated by the server"
        if packet[DNS].rd == 1:
             return ". . . . Answer authenticated: Answer/authority portion was authenticated by the server"

    def ReplyCOde(self,packet):
        if packet[DNS].rcode == 0:
            return ". . . . Reply code: No error - request completed successfully (0)"
        if packet[DNS].rcode == 1:
            return ". . . . Reply pcode: Format error (1)"
        if packet[DNS].rcode == 2:
            return ". . . . Reply code: Server error (2)"
        if packet[DNS].rcode == 3:
            return ". . . . Reply code: Name error (3)"
        if packet[DNS].rcode == 4:
            return ". . . . Reply code: Not Implemented  (4)"
        if packet[DNS].rcode == 5:
            return ". . . . Reply code: Refused  (5)"

    def TotalQuestions(self,packet):
        return packet[DNS].qdcount

    def TotalAnswersRR(self,packet):
        return packet[DNS].ancount

    def TotalAuthorityRR(self,packet):
        return packet[DNS].nscount

    def TotalAdditionalRR(self,packet):
        return packet[DNS].arcount


    def TcpFlags(self,packet):
        if packet[TCP].flags == 1:
            return "FIN"
        if packet[TCP].flags == 2:
            return "SYN"
        if packet[TCP].flags == 4:
            return "RST"
        if packet[TCP].flags == 8:
            return "PSH"
        if packet[TCP].flags == 16:
            return "ACK"
        if packet[TCP].flags == 32:
            return "URG"
        if packet[TCP].flags == 64:
            return "ECE"
        if packet[TCP].flags == 128:
            return "CWR"
        if packet[TCP].flags == 18:
            return "SYN-ACK"
        if packet[TCP].flags == 24: # ack = 16 , psh = 8 :  (16 + 8)
            return "PSH-ACK"
        if packet[TCP].flags == 48:
            return "URG-ACK"
        if packet[TCP].flags == 56:
            return "URG-PSH-ACK"
        if packet[TCP].flags == 17:
            return "FIN-ACK"
        if packet[TCP].flags == 20:
            return "RST-ACK"

    def DnsqrQtype(self,packet,x):
        if packet[DNSQR][x].qtype == 1:
            return "A (Host Address) (1)"
        if packet[DNSQR][x].qtype == 12:
            return "PTR (domain name pointer) (12)"
        if packet[DNSQR][x].qtype ==33:
            return "SRV (Server Selection) (33)"
        if packet[DNSQR][x].qtype == 28:
            return "AAAA (IPv6 Address) (28)"
        if packet[DNSQR][x].qtype == 255:
            return "* (A request for all records the server/cache has available)"
        return packet[DNSQR][x].qtype

    def DnsqrQClass(self,packet,x):
        if packet[DNSQR][x].qclass == 1:
            return "IN (0x001)"

    def DnsrrQtype(self,packet,x):
        if packet[DNSRR][x].type == 1:
            return "A (Host Address) (1)"
        if packet[DNSRR][x].type == 12:
            return "PTR (domain name pointer) (12)"
        if packet[DNSRR][x].type ==33:
            return "SRV (Server Selection) (33)"
        if packet[DNSRR][x].type == 28:
            return "AAAA (IPv6 Address) (28)"
        if packet[DNSRR][x].type == 255:
            return "* (A request for all records the server/cache has available)"
        if packet[DNSRR][x].type == 5:
            return "CNAME (Canonical NAME for an alias) (5)"
        if packet[DNSRR][x].type == 6:
            return "A (Host Address) (6)"
        return packet[DNSRR][x].type

    def DnsrrQClass(self,packet,x):
        if packet[DNSRR][x].rclass == 1:
            return "IN (0x001)"
        return packet[DNSRR][x].rclass

    def DnsAuthType(self,packet,x):
        if packet[DNSRR][x].type == 1:
            return "A (Host Address) (1)"
        if packet[DNSRR][x].type == 12:
            return "PTR (domain name pointer) (12)"
        if packet[DNSRR][x].type ==33:
            return "SRV (Server Selection) (33)"
        if packet[DNSRR][x].type == 28:
            return "AAAA (IPv6 Address) (28)"
        if packet[DNSRR][x].type == 255:
            return "* (A request for all records the server/cache has available)"
        if packet[DNSRR][x].type == 5:
            return "CNAME (Canonical NAME for an alias) (5)"
        if packet[DNSRR][x].type == 6:
            return "A (Host Address) (6)"
        return packet[DNSRR][x].type

    def DnsAuthRClass(self,packet,x):
        if packet[DNSRR][x].rclass == 1:
            return "IN (0x001)"
        return packet[DNSRR][x].rclass

    def IcmpType(self,packet):
        typeArr = ["Echo Reply", "Unassigned", "Unassaigned", "Destination Unreachable","Source Quench"," Redirect"," Alternate Host Address","Unassigned ","Echo ","Router Advertisement ","Router Selection  ","Time Exceeded","Parameter Problem ","Timestamp ","Timestamp Reply ","Information Request ","Information Reply ","Address Mask Request ","Address Mask Reply ","Reserved (for Security)" ] #"," "," "," "," "," "," "," "," ",
        for x in range(20,29):
            typeArr.append("Reserved (for Robustness Experiment)")
        typeArr2 = ["Traceroute ","Datagram Conversion Error ","Mobile Host Redirect ","IPv6 Where-Are-You ","IPv6 I-Am-Here ","Mobile Registration Request ","Mobile Registration Reply ","Domain Name Request ","Domain Name Reply ","SKIP  ","Photuris "]
        finalList = typeArr + typeArr2
        return finalList[packet[0][ICMP].type]

    def IcmpCode(self,packet):
        return packet[ICMP].code

    def ArpHwType(self,packet): # hardware type in arp
        if packet[ARP].hwtype == 1:
            return "Ethernet (1)"
        else:
            return packet[ARP].hwtype

    def ArpProType(self,packet):
        if packet[ARP].ptype == 1:
            return "IPv4 (0x800)"
        else:
            return packet[ARP].ptype

    def ArpOpCode(self,packet):
        if packet[ARP].op == 1:
            return "request (1): Who has " + str(packet[ARP].pdst) + "? Tell " + str(packet[ARP].psrc)
        if packet[ARP].op == 2:
            return "reply (2): " +  str(packet[ARP].psrc) + " is at " + str(str(packet[ARP].hwsrc))


class ExportPage:
    def __init__(self, all_packets):
        self.all_packets = all_packets
        self.export_page = Tk()
        self.file_info_label = Label(self.export_page, text="The file will be saved as a .csv file in the current directory.")
        self.file_info_label.grid(row=0, column=0)
        self.filename_entry = Entry(self.export_page)
        self.filename_entry.grid(row=2, column=1)
        self.filename_label = Label(self.export_page, text="File Name:")
        self.filename_label.grid(row=2, column=0, sticky=E)
        self.save_button = Button(self.export_page, text="Save", command=self.save)
        self.save_button.grid(row=3, column=1, sticky=E)
        self.save_button.config(bg='yellow')

    def save(self):
        name = self.filename_entry.get()
        export_list = [["Number", "Date", "Time", "Source", "Destination", "Protocol"]]
        packet_list = []

        for x in range(len(self.all_packets)):
            packet_list.append(str(self.all_packets[x][2]))  # number
            packet_list.append(self.date_with_periods(str(self.all_packets[x][3].split(" ")[0])))  # date
            packet_list.append(str(self.all_packets[x][3].split(" ")[1][0:8]))  # time
            packet_list.append(str(self.all_packets[x][4]))  # source
            packet_list.append(str(self.all_packets[x][5]))  # destination
            packet_list.append(str(self.all_packets[x][6]))  # protocol
            export_list.append(packet_list)
            packet_list = []

        cwd_path = os.getcwd()  # current working directory path
        path = os.path.join(cwd_path, name+".csv")  # python cant end string with "\"
        if os.path.isfile(path):  # if file name exists in current directory
            name_exists_label = Label(self.export_page, text="A file with this name alredy exists! Please enter a new name.")
            name_exists_label.config(fg='white', bg='red')
            name_exists_label.grid(row=1, column=0)

        else:
            #csv.field_size_limit(200000)
            writer = csv.writer(open(path, 'w'))
            for row in export_list:
                writer.writerow(row)
            self.export_page.destroy()  # close export page

    def date_with_periods(self, date):  # 26.06.2018 instead of 2018-06-26 (this shows '#####' in excel)
        year = date.split("-")[0]
        month = date.split("-")[1]
        day = date.split("-")[2]
        new_date = day + "." + month + "." + year
        return new_date

class HelpPage:
    def __init__(self):

        master = Tk()
        master.geometry("500x150")
        t1 = Label(master, text="Welcome to WireFish!")
        t1.config(font=("Courier", 20))
        t1.pack()
        t2 = Label(master, text="How to use filters")
        t2.pack()
        t3 = Label(master, text="to filter by protocol: name of protocol in all caps, example: 'DNS' ")
        t3.pack()
        t4 = Label(master, text="to filter by source address: 'src: ' + MAC/IP address, example: 'src:12.0.0.7' ")
        t4.pack()
        t5 = Label(master, text="to filter by destination address: 'dst: ' + MAC/IP address, example: 'dst:12.0.0.7' ")
        t5.pack()
        t6 = Label(master, text="to filter by packet number: 'num: ' + packet number, example: 'num: 47' ")
        t6.pack()

        mainloop()


class WireFishMainPage(Frame):

    def __init__(self, parent):  # constructor
        Frame.__init__(self, parent)
        self.parent = parent
        self.to_sniff = True
        self.all_packets = []
        self.is_sniffing = False
        self.parent.title("WireFish")
        self.parent.grid_rowconfigure(5, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.config(background="yellow")

        # Define the different GUI widgets

        self.filter_label = Label(self.parent, text="Filter:")
        self.filter_entry = Entry(self.parent)
        self.filter_entry.config(width=40)
        self.filter_entry.bind("<Button-1>", self.clear_search)
        self.filter_label.grid(row=0, column=0, sticky=E)
        self.filter_entry.grid(row=0, column=1)

        self.search_button = Button(self.parent, text="Search", width=8, state=DISABLED, command=self.filter_search)
        self.search_button.grid(row=0, column=4, sticky=W)
        self.clear_button = Button(self.parent, text="Clear", width=8, command=self.clear)
        self.clear_button.grid(row=3, column=0, sticky=W)
        self.clear_button.config(bg='light blue')

        self.show_all_button = Button(self.parent, text="Show All", width=8, command=self.show_all)
        self.show_all_button.grid(row=2, column=0, sticky=W)

        self.delete_button = Button(self.parent, text="Delete", width=8, command=self.delete_file)
        self.delete_button.grid(row=2, column=4, sticky=E)

        self.export_button = Button(self.parent, text="Export", width=8, command=self.export)
        self.export_button.grid(row=3, column=4, sticky=E)
        self.export_button.config(bg='red')

        self.start_button = Button(self.parent, text="?", width=8, command=self.help)
        self.start_button.grid(row=1, column=4, sticky=E)

        self.start_button = Button(self.parent, text="Start", width=8, command=self.go_to_sniffing)
        self.start_button.grid(row=0, column=0, sticky=W)

        self.stop_button = Button(self.parent, text="Stop", width=8, state=DISABLED, command=self.stop_sniffing)
        self.stop_button.grid(row=1, column=0, sticky=W)

        # Set the treeview
        self.tree = ttk.Treeview(self.parent, columns=('Dose', 'Modification date', 'Hello', 'Protocol'))
        self.tree.scrollable = True  # SCROLLABLE
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.heading('#0', text='Number')
        self.tree.heading('#1', text='Time')
        self.tree.heading('#2', text='Source')
        self.tree.heading('#3', text='Destination')
        self.tree.heading('#4', text='Protocol')
        self.tree.column('#1', stretch=YES)
        self.tree.column('#2', stretch=YES)
        self.tree.column('#0', stretch=YES)
        self.tree.column('#3', stretch=YES)
        self.tree.column('#4', stretch=YES)
        self.tree.grid(row=5, columnspan=5, sticky='nsew')
        self.treeview = self.tree
        self.i = 0

    def clear_search(self, event):
        self.filter_entry.delete(0, END)
        self.filter_entry.config(bg='white')

    def clear(self):
        items = self.tree.get_children()
        for item in items:
            self.tree.delete(item)  # clears tree
        self.i = 0
        self.all_packets = []
        self.to_sniff = True
        self.stop_sniffing()
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def filter_search(self):
        filter = self.filter_entry.get()
        items = self.tree.get_children()
        for item in items:
            self.tree.delete(item)  # clears tree

        split_filter = filter.split(" ")
        is_found = False
        if len(filter.split(" ")) == 1:  # filter is protocol
            for x in range(len(self.all_packets)):
                if filter in self.all_packets[x][7] or self.all_packets[x][6].split(" ")[0] == filter:
                    is_found = True
                    self.treeview.insert('', '0', text=str(str(self.all_packets[x][2])), values=(str(self.all_packets[x][3]), str(self.all_packets[x][4]), str(self.all_packets[x][5]), str(self.all_packets[x][6])), tags=(str(self.all_packets[x][8]),))
            if is_found == False:
                if filter in ["Ether", "IP", "ICMP", "ARP", "TCP", "UDP", "DNS", "HTTP", "SSDP"]:
                    self.filter_entry.delete(0, END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Protocol not found")
                else:
                    self.filter_entry.delete(0, END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Invalid protocol")

        elif split_filter[0] == "dst:":
            is_found = False
            for x in range(len(self.all_packets)):
                if self.all_packets[x][5] == split_filter[1]:
                    is_found = True
                    self.treeview.insert('', '0', text=str(str(self.all_packets[x][2])), values=(str(self.all_packets[x][3]), str(self.all_packets[x][4]), str(self.all_packets[x][5]), str(self.all_packets[x][6])), tags = str(self.all_packets[x][7])+",")

            if is_found == False:
                if self.filter_is_valid(filter):  # if address is valid but not found
                    self.filter_entry.delete(0, END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Address not found")

                else:  # invalid address
                    self.filter_entry.delete(0, END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Invalid address")

        elif split_filter[0] == "src:":
            is_found = False
            for x in range(len(self.all_packets)):
                if self.all_packets[x][4] == split_filter[1]:
                    is_found = True
                    self.treeview.insert('', '0', text=str(str(self.all_packets[x][2])), values=(str(self.all_packets[x][3]), str(self.all_packets[x][4]), str(self.all_packets[x][5]), str(self.all_packets[x][6])), tags = str(self.all_packets[x][7])+",")
            if is_found == False:
                if self.filter_is_valid(filter):  # if address is valid but not found
                    self.filter_entry.delete(0,END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Address not found")

                else:  # invalid address
                    self.filter_entry.delete(0, END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Invalid address")

        elif split_filter[0] == "num:":
            for x in range(len(self.all_packets)):
                if self.all_packets[x][2] == split_filter[1]:
                    is_found = True
                    self.treeview.insert('', '0', text=str(str(self.all_packets[x][2])), values=(str(self.all_packets[x][3]),str(self.all_packets[x][4]), str(self.all_packets[x][5]), str(self.all_packets[x][6])), tags = str(self.all_packets[x][7])+",")
            if is_found == False:
                    self.filter_entry.delete(0,END)
                    self.filter_entry.config(bg='red')
                    self.filter_entry.insert(0, "Error: Packet number out of range")

        else:
            self.filter_entry.delete(0, END)
            self.filter_entry.config(bg='red')
            self.filter_entry.insert(0, "Error: Invalid filter")

    def stop_sniffing(self):
        self.to_sniff = False
        self.stop_button.config(state=DISABLED)
        self.search_button.config(state=NORMAL)
        self.start_button.config(state=NORMAL)
        self.clear_button.config(state=NORMAL)

    def go_to_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=DISABLED)
        self.search_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.to_sniff = True
        t = threading.Thread(target=self.start_sniffing)
        t.start()

    def show_all(self):
        items = self.tree.get_children()
        for item in items:
            self.tree.delete(item)  # clears tree
        for x in range(self.i):
            self.treeview.insert('', '0', text=str(str(self.all_packets[x][2])), values=(str(self.all_packets[x][3]), str(self.all_packets[x][4]), str(self.all_packets[x][5]), str(self.all_packets[x][6])), tags = self.all_packets[x][8],)

    def on_double_click(self, event):  # when an item is double clicked
        try:
            selected_item = self.tree.selection()[0]  # selected item
            selected_item_num = self.tree.item(selected_item, 'text')  # number of selected item
            selected_item_values = self.tree.item(selected_item, 'values')  # date,time,src,dst,prot. of selected item
            title = " ".join(str(x) for x in selected_item_values)  # convert list to string

            for x in range(len(self.all_packets)):
                new_item = self.all_packets[x]
                new_item_num = self.all_packets[x][2]
                if selected_item_num == new_item_num:

                    packet = new_item[7]
                    packet_time = self.all_packets[int(new_item_num)-1][3]
                    packet_len = str(len(packet))
                    packet_prot = self.all_packets[x][6]

                    NewPage = PacketPage(title, packet, packet_time, new_item_num, packet_len, packet_prot)
        except:
            pass

    def filter_is_valid(self, filter):
        address = filter.split(" ")[1]
        if len(address.split(".")) == 4 or len(filter.split(".")) == 4:  # ipv4 or ipv6
            for num in address.split("."):
                if num.isdigit():
                    if int(num) > 255:
                        return False
                else:
                    return False
            return True
        elif len(address.split(":")) == 6:
            for item in address.split(":"):
                if int(item, 16) > 255:
                    return False
            return True
        return False

    def start_sniffing(self):
        try:
            while self.to_sniff:
                packets = sniff(count=1)  # lfilter = self.filter_dns)
                packet = packets[0]
                if Ether in packet and ARP in packet:
                    self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[Ether].src), str(packet[Ether].dst), "ARP"), tags = ('arp',))  # To insert a new top-level item, make this argument an empty string ''
                    # self.tree.bind("<Double-1>", self.on_double_click) ##############
                    self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[Ether].src), str(packet[Ether].dst), "ARP", packet, "arp"))
                    self.i += 1
                else:
                    if IP in packet and ICMP in packet:
                        self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "ICMP"), tags = ('icmp',))  # This argument ('0') specifies the position among this parent's children where you want the new item to be added. For example, to insert the item as the new first child, use a value of zero
                        self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "ICMP", packet, "icmp"))
                    if IP in packet and TCP in packet:
                        if Raw in packet:
                            if str(packet[Raw]).find("ssdp:discover") != 1:
                                self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "SSDP"), tags = ('ssdp',))
                                self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "SSDP", packet, "ssdp"))
                                self.i += 1
                            elif str(packet[Raw]).startswith('GET'):  # http GET request
                                self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP - GET"), tags = ('http',))
                                self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP - GET", packet, "http"))
                                self.i += 1
                            elif str(packet[Raw]).startswith('POST'):  # http POST request
                                self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP - POST"), tags = ('http',))
                                self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP . . . POST request", packet, "http"))
                                self.i = self.i + 1
                            elif str(packet[Raw]).startswith('HTTP'):  # http reply
                                self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP - REPLY"), tags = ('http',))
                                self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "HTTP . . . reply", packet, "http"))
                                self.i = self.i + 1
                        else:
                            self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "TCP"), tags = ('tcp',))
                            self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "TCP", packet, "tcp"))
                            self.i += 1
                    elif IP in packet and UDP in packet:
                        if DNS in packet:
                            self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "DNS"), tags = ('dns',))
                            self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "DNS", packet, "dns"))
                        else:
                            self.treeview.insert('', '0', text=str(self.i+1), values=(str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "UDP"), tags = ('udp',))
                            self.all_packets.append(('', '0', str(self.i+1), str(datetime.now()), str(packet[IP].src), str(packet[IP].dst), "UDP", packet, "udp"))
                        # Increment counter
                        self.i += 1

                self.treeview.tag_configure('arp', background='red')
                self.treeview.tag_configure('icmp', background='orange')
                self.treeview.tag_configure('ssdp', background='yellow')
                self.treeview.tag_configure('http', background='light green')
                self.treeview.tag_configure('tcp', background='light blue')
                self.treeview.tag_configure('dns', background='blue')
                self.treeview.tag_configure('udp', background='pink')
        except:
            pass

    def help(self):
        """

        :return:
        """
        newHelpPage = HelpPage()

    def export(self):
        """

        :return:
        """
        newExportPage = ExportPage(self.all_packets)

    def delete_file(self):
        """

        :return:
        """
        myfile = filedialog.askopenfilename()
        if os.path.isfile(myfile):
            os.remove(myfile)
        else:  # Show an error
            print("Error: %s file not found" % myfile)


def main():
    """

    :return:
    """
    root = Tk()
    main_window = WireFishMainPage(root)  # WireFishMainPage = class
    root.mainloop()


if __name__ == "__main__":
    main()
