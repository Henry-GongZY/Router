#pragma once

#include<pcap.h>
#include<iostream>
#define INET_ADDRSTRLEN 22

using namespace std;

struct ipmacTableEntry {
    ipmacTableEntry* next;
    char ip[INET_ADDRSTRLEN];
    BYTE mac[6];
    ipmacTableEntry() {
        next = nullptr;
    }
    ipmacTableEntry(char* ip, BYTE* mac) {
        strcpy(this->ip, ip);
        for (int i = 0; i < 6; i++) {
            this->mac[i] = mac[i];
        }
        next = nullptr;
    }
    void insert(ipmacTableEntry* x) {
        ipmacTableEntry* curr = this;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = x;
    }
    ipmacTableEntry* find(char* ip) {
        ipmacTableEntry* curr = this->next;
        while (curr) {
            if (strcmp(curr->ip, ip) == 0) {
                return curr;
            }
            curr = curr->next;
        }
        return nullptr;
    }
};

