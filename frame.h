#pragma once

#include<iostream>
#include<pcap.h>

#pragma pack(1)

typedef struct FrameHeader_t {//本次实验需要的内容都在该结构中
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}frame_header;

typedef struct IPHeader_t {
    BYTE Ver_HLen;
    BYTE TOS;
    WORD TotalLen;
    WORD ID;
    WORD Flag_Segment;
    BYTE TTL;
    BYTE Protocol;
    WORD Checksum;
    ULONG SrcIP;
    ULONG DstIP;
}ip_header;

typedef struct Icmp_t {
    u_char type;
    u_char code;
    WORD checksum;
    WORD id;
    WORD seq;
    char data[64];
}icmp_data;

typedef struct ICMPPacket {
    FrameHeader_t FrameHeader;
    ip_header IPHeader;
    icmp_data icmp;
}icmp_packet;

typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader;
    WORD HardwareType;
    WORD ProtocolType;
    BYTE HLen;
    BYTE PLen;
    WORD Operation;
    BYTE SendHa[6];
    DWORD SendIP;
    BYTE RecvHa[6];
    DWORD RecvIP;
}arp_frame;

#pragma pack()