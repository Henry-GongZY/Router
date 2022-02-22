#pragma once
#include<iostream>
#include<pcap.h>


WORD add(WORD a, WORD b) {
    WORD sum = ((a + b) & 0xFFFF) + ((a + b) >> 16);
    return sum;
}

WORD checksum(ICMPPacket data) {
    WORD sum;
    struct in_addr src;
    memcpy(&src, &data.IPHeader.SrcIP, 4);
    struct in_addr dst;
    memcpy(&dst, &data.IPHeader.DstIP, 4);

    sum = add((data.IPHeader.Ver_HLen << 8) + data.IPHeader.TOS, ntohs(data.IPHeader.TotalLen));
    sum = add(sum, ntohs(data.IPHeader.ID));
    sum = add(sum, ntohs(data.IPHeader.Flag_Segment));
    sum = add(sum, (data.IPHeader.TTL << 8) + data.IPHeader.Protocol);
    sum = add(sum, ntohs(src.S_un.S_un_w.s_w1));
    sum = add(sum, ntohs(src.S_un.S_un_w.s_w2));
    sum = add(sum, ntohs(dst.S_un.S_un_w.s_w1));
    sum = add(sum, ntohs(dst.S_un.S_un_w.s_w2));
    return ~sum;
}