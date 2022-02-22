#include<pcap.h>
#include<iostream>
#include<WinSock2.h>
#include"ipmacTableEntry.h"
#include"routeTable.h"
#include"frame.h"
#include"cksum.h"

using std::cin;
using std::cout;
using std::endl;

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

//网卡是否开启
bool interfaceon = false;

//主机网卡双ip和mac地址
char hostip1[INET_ADDRSTRLEN];
char hostip2[INET_ADDRSTRLEN];
BYTE hostMAC[6];

//是否拿到主机/远端arp
bool hostget = false;
bool remoteget = false;

//远端ip和mac
char remoteip[INET_ADDRSTRLEN];
BYTE remoteMAC[6];

//路由表
routeTableEntry* routeTable = new routeTableEntry();
//ip_mac映射表
ipmacTableEntry* ipmacTable = new ipmacTableEntry();

DWORD WINAPI arpparse(LPVOID p) {
    pcap_if_t* d = (pcap_if_t*)(LPVOID)p;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle;
    arp_frame* IPPacket;
    if ((adhandle = pcap_open(d->name, 70000, 1, 1000, NULL, errbuf)) == NULL) {
        cout << "打开失败" << endl;
    }
    else {
        //启动成功
        interfaceon = true;
    }
    while (true) {
        pcap_pkthdr* header;
        u_char* pkt_data;
        if (pcap_next_ex(adhandle, &header, (const u_char**)&pkt_data) != 1) {
            continue;
        }
        else {
            BYTE* desmac;
            BYTE* srcmac;
            WORD type;
            IPPacket = (arp_frame*)pkt_data;
            desmac = IPPacket->FrameHeader.DesMAC;//目的地址
            srcmac = IPPacket->FrameHeader.SrcMAC;//源地址
            type = ntohs(IPPacket->FrameHeader.FrameType);
            //解析arp包
            if (type == 0x806) {
                if (IPPacket->FrameHeader.DesMAC[0] == 0x55) {//来自本机，打印出来
                    for (int i = 0; i < 6; i++) {
                        hostMAC[i] = IPPacket->FrameHeader.SrcMAC[i];
                    }
                    printf("本机MAC地址为：%02x:%02x:%02x:%02x:%02x:%02x:\n", *srcmac, *(srcmac + 1), *(srcmac + 2), *(srcmac + 3), *(srcmac + 4), *(srcmac + 5));
                    cout << "----------------------------------------------------" << endl;
                    hostget = true; //拿到本机
                }
                else {//来自远端，悄悄存储
                    struct in_addr in1;
                    memcpy(&in1, &IPPacket->SendIP, 4);
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &in1, str, sizeof(str));
                    if (strcmp(str, remoteip) == 0) {
                        for (int i = 0; i < 6; i++) {
                            remoteMAC[i] = IPPacket->FrameHeader.SrcMAC[i];
                        }
                        remoteget = true; //拿到远端
                    }
                }
            }

        }
    }
    return 0;
}

DWORD WINAPI alttable(LPVOID p) {
    int change;
    while (true) {
        cin >> change;
        switch (change) {
            case 1: {
                char des[INET_ADDRSTRLEN];
                char netmask[INET_ADDRSTRLEN];
                char nextjump[INET_ADDRSTRLEN];
                cout << "请输入目的网络" << endl;
                cin >> des;
                cout << "请输入网络掩码" << endl;
                cin >> netmask;
                cout << "请输入下一跳步" << endl;
                cin >> nextjump;
                routeTableEntry* temp = new routeTableEntry(des, netmask, nextjump);
                routeTable->insert(temp);
                break;
            }
            case 2: {
                char des[INET_ADDRSTRLEN];
                char netmask[INET_ADDRSTRLEN];
                char nextjump[INET_ADDRSTRLEN];
                cout << "请输入目的网络" << endl;
                cin >> des;
                cout << "请输入网络掩码" << endl;
                cin >> netmask;
                cout << "请输入下一跳步" << endl;
                cin >> nextjump;
                routeTable->Delete(des, netmask, nextjump);
                break;
            }
            case 3: {
                routeTable->print();
            }
        }
    }
}

int main() {

    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    pcap_addr_t* a;
    int i = 0,num;
    char errbuf[PCAP_ERRBUF_SIZE];
    ICMPPacket* IPPacket;

    pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf);

    for (d = alldevs; d != nullptr; d = d->next) {//从第一个网卡开始遍历
        i++;//打印设备具体信息
        cout << "网卡" << i << endl;
        cout << "name:" << d->name << endl;
        num = 0;

        for (a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {//如果地址类型为ip地址
                num++;
                cout << "IP" << num <<':'<<endl;

                struct sockaddr_in* sock1 = (struct sockaddr_in*)  a->addr;
                struct in_addr in1 = sock1->sin_addr;
                char str1[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in1, str1, sizeof(str1));

                struct sockaddr_in* sock2 = (struct sockaddr_in*)  a->netmask;
                struct in_addr in2 = sock2->sin_addr;
                char str2[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in2, str2, sizeof(str2));

                cout << "IP地址" << str1 << endl << "子网掩码" << str2 << endl;
            }
        }

        cout << "------------------------------------------------" << endl;
    }

    cout << "选择网卡" << endl;
    cin >> num;
    if (num<1 || num>i) {
        cout << "超出范围" << endl;
        return 0;
    }
    d = alldevs;
    for (i = 0; i < num - 1; i++) {
        d = d->next;
    }
    adhandle = pcap_open(d->name, 70000, 1, 1000, NULL, errbuf);

    HANDLE change = CreateThread(nullptr, 0, alttable, nullptr, 0, nullptr);

    //包装请求本机的arp报文
    arp_frame ARPFrame;
    for (int j = 0; j < 6; j++) {
        ARPFrame.FrameHeader.DesMAC[j] = 0xff;
        ARPFrame.FrameHeader.SrcMAC[j] = 0x55;
        ARPFrame.SendHa[j] = 0x55;
        ARPFrame.RecvHa[j] = 0x00;
    }
    ARPFrame.FrameHeader.FrameType = htons(0x0806);
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800);
    ARPFrame.HLen = 6;
    ARPFrame.PLen = 4;
    ARPFrame.Operation = htons(0x0001);
    //使用虚拟ip地址
    ARPFrame.SendIP = inet_addr("112.112.112.112");

    int times = 0;
    a = d->addresses;
    for (a = d->addresses; a != nullptr; a = a->next) {
        if (a->addr->sa_family == AF_INET) {
            struct in_addr in = ((struct sockaddr_in*) a->addr)->sin_addr;
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in, str, sizeof(str));
            if (times == 0) {
                strcpy(hostip1, str);
                times++;
            }
            else {
                strcpy(hostip2, str);
            }
            ARPFrame.RecvIP = inet_addr(str);
            char* destination = str;

            struct in_addr in2 = ((struct sockaddr_in*)  a->netmask)->sin_addr;
            char str2[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in2, str2, sizeof(str2));
            char* mask = str2;

            char net[INET_ADDRSTRLEN] = "0.0.0.0";
            char* net1 = net;

            //根据本地ip获取子网，并插入路由表
            ip2net(destination, mask, net);
            routeTableEntry* temp = new routeTableEntry(net, mask, net1);
            temp->direct = true;
            routeTable->insert(temp);
        }
    }

    //启动arp解析线程
    HANDLE con = CreateThread(nullptr, 0, arpparse, (LPVOID) d, 0, nullptr);

    //网卡启动，可正常接收
    while (!interfaceon) {}

    //发送arp报文，此时接收线程已经就绪
    pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame));

    //直到正常获取本机ip地址为止
    while (!hostget) {}

    while (true) {
        pcap_pkthdr* header;
        u_char* pkt_data;
        //接受包
        if (pcap_next_ex(adhandle, &header, (const u_char**)&pkt_data)) {
            BYTE* desmac;
            BYTE* srcmac;
            WORD type;
            //解析源ip和目的ip
            IPPacket = (ICMPPacket*)pkt_data;
            desmac = IPPacket->FrameHeader.DesMAC;
            srcmac = IPPacket->FrameHeader.SrcMAC;
            type = ntohs(IPPacket->FrameHeader.FrameType);

            struct in_addr in1;
            memcpy(&in1, &IPPacket->IPHeader.SrcIP, 4);
            char str1[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in1, str1, sizeof(str1));

            struct in_addr in2;
            memcpy(&in2, &IPPacket->IPHeader.DstIP, 4);
            char str2[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in2, str2, sizeof(str2));

            //不是到本机的包
            for (int j = 0; j < 6; j++) {
                if (desmac[j] != hostMAC[j])
                    continue;
            }
            //不需要转发
            if (strcmp(str1, hostip1) == 0 || strcmp(str2, hostip2) == 0) {
                continue;
            }
            //不是icmp协议
            if (IPPacket->IPHeader.Protocol != 1) {  //不是icmp不收
                continue;
            }
            //输出为地址格式
            cout << "收到：" << endl;
            cout << "源IP地址" << str1 << endl;
            cout << "目的IP地址" << str2 << endl;
            printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n", *desmac, *(desmac + 1), *(desmac + 2), *(desmac + 3), *(desmac + 4), *(desmac + 5));
            printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n", *srcmac, *(srcmac + 1), *(srcmac + 2), *(srcmac + 3), *(srcmac + 4), *(srcmac + 5));
            printf("类型： ", type);
            switch (type) {//输出类型
                case 0x800:
                    cout << "IP" << endl;
                    break;
                case 0x806:
                    cout << "ARP" << endl;
            }
            cout << "---------------------------------------------------------" << endl;

            routeTableEntry* temp = findroute(routeTable, str2);
            if (temp != nullptr) { //在路由表中查到
                ipmacTableEntry *entry;
                if (temp->direct) { //直接投递查目的IP
                    entry = ipmacTable->find(str2);
                } else {//查下一跳步的IP
                    entry = ipmacTable->find(temp->nextjump);
                }
                if (entry) {//ip-mac映射查到了
                    BYTE *nextMAC = entry->mac;
                    for (int j = 0; j < 6; j++) {
                        IPPacket->FrameHeader.SrcMAC[j] = hostMAC[j];
                        IPPacket->FrameHeader.DesMAC[j] = nextMAC[j];
                    }
                    //计算TTL与首部校验和
                    IPPacket->IPHeader.TTL--;
                    IPPacket->IPHeader.Checksum = htons(checksum(*IPPacket));
                    pcap_sendpacket(adhandle, (u_char *) IPPacket, sizeof(*IPPacket));
                } else {
                    //发送arp询问，打包
                    arp_frame ARPframe;

                    for (int j = 0; j < 6; j++) {
                        ARPframe.FrameHeader.DesMAC[j] = 0xff;
                        ARPframe.FrameHeader.SrcMAC[j] = hostMAC[j];
                        ARPframe.SendHa[j] = hostMAC[j];
                        ARPframe.RecvHa[j] = 0x00;
                    }
                    ARPframe.FrameHeader.FrameType = htons(0x0806);
                    ARPframe.HardwareType = htons(0x0001);
                    ARPframe.ProtocolType = htons(0x0800);
                    ARPframe.HLen = 6;
                    ARPframe.PLen = 4;
                    ARPframe.Operation = htons(0x0001);

                    //直接投递
                    if (temp->direct) {
                        ARPframe.RecvIP = inet_addr(str2);
                        strcpy(remoteip, str2);
                    } else {  //下一跳
                        ARPframe.RecvIP = inet_addr(temp->nextjump);
                        strcpy(remoteip, temp->nextjump);
                    }

                    remoteget = false;
                    pcap_sendpacket(adhandle, (u_char *) &ARPframe, sizeof(ARPframe));

                    //阻塞直至获取到远端ARP
                    while (!remoteget) {}

                    //将获得的ip，mac对插入表中
                    ipmacTableEntry *entry2;
                    entry2 = new ipmacTableEntry(remoteip, remoteMAC);
                    ipmacTable->insert(entry2);

                    //改变mac地址
                    for (int j = 0; j < 6; j++) {
                        IPPacket->FrameHeader.SrcMAC[j] = hostMAC[j];
                        IPPacket->FrameHeader.DesMAC[j] = remoteMAC[j];
                    }
                    //重新计算校验和和TTL
                    IPPacket->IPHeader.TTL--;
                    IPPacket->IPHeader.Checksum = htons(checksum(*IPPacket));
                    pcap_sendpacket(adhandle, (u_char *) IPPacket, sizeof(*IPPacket));
                }
            }

            cout << "转发：" << endl;
            memcpy(&in1, &IPPacket->IPHeader.SrcIP, 4);
            inet_ntop(AF_INET, &in1, str1, sizeof(str1));
            memcpy(&in2, &IPPacket->IPHeader.DstIP, 4);
            inet_ntop(AF_INET, &in2, str2, sizeof(str2));
            //输出为地址格式
            cout << "源IP地址" << str1 << endl;
            cout << "目的IP地址" << str2 << endl;
            printf("目的MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n", *IPPacket->FrameHeader.DesMAC, *(IPPacket->FrameHeader.DesMAC + 1), *(IPPacket->FrameHeader.DesMAC + 2), *(IPPacket->FrameHeader.DesMAC + 3), *(IPPacket->FrameHeader.DesMAC + 4), *(IPPacket->FrameHeader.DesMAC + 5));
            printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n", *IPPacket->FrameHeader.SrcMAC, *(IPPacket->FrameHeader.SrcMAC + 1), *(IPPacket->FrameHeader.SrcMAC + 2), *(IPPacket->FrameHeader.SrcMAC + 3), *(IPPacket->FrameHeader.SrcMAC + 4), *(IPPacket->FrameHeader.SrcMAC + 5));
            printf("类型： ", type);
            switch (type) {//输出类型
                case 0x800:
                    cout << "IP" << endl;
                    break;
                case 0x806:
                    cout << "ARP" << endl;
            }

            cout << "---------------------------------------------------------" << endl;
        }
    }
    pcap_freealldevs(alldevs);
    return 0;
}