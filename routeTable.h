#pragma once

#include<pcap.h>
#include<iostream>
using namespace std;
#define INET_ADDRSTRLEN 22

struct routeTableEntry {
    routeTableEntry* next;
    char destination[INET_ADDRSTRLEN];
    char mask[INET_ADDRSTRLEN];
    char nextjump[INET_ADDRSTRLEN];
    bool direct;
    routeTableEntry() {
        next = nullptr;
    }
    routeTableEntry(char* destination, char* mask, char* nextjump) {
        next = nullptr;
        direct = false;
        strcpy(this->destination, destination);
        strcpy(this->mask, mask);
        strcpy(this->nextjump, nextjump);
    }
    void insert(routeTableEntry* x) {
        routeTableEntry* check = this;
        while (check->next) {
            check = check->next;
        }
        check->next = x;
    }
    void Delete(char* destination, char* mask, char* nextjump) {
        routeTableEntry* check = this;
        while (check->next) {
            if (!strcmp(check->next->destination, destination) && !strcmp(check->next->mask, mask)
            && !strcmp(check->next->nextjump, nextjump)){
                routeTableEntry* temp = check->next->next;
                check->next = nullptr;
                check->next = temp;
            }
            check = check->next;
        }
    }
    void print() {
        routeTableEntry* curr = next;
        while (curr) {
            cout << "目的网络：" << curr->destination << endl;
            cout << "网络掩码：" << curr->mask << endl;
            if (curr->direct) {
                cout << "直接投递" << endl;
            }
            else {
                cout << "下一跳" << curr->nextjump << endl;
            }
            curr = curr->next;
        }
    }
};

void ip2net(char* ip, char* mask, char* netnum) {
    DWORD net = inet_addr(ip) & inet_addr(mask);
    struct in_addr in1;
    memcpy(&in1, &netnum, 4);
    char str1[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in1, str1, sizeof(str1));
    strcpy(netnum, str1);
}

routeTableEntry* findroute(routeTableEntry* root, char* destination) {
    routeTableEntry* curr = root->next;
    routeTableEntry* tmp = nullptr;
    while (curr) {
        char* net = new char[22];
        ip2net(destination, curr->mask, net);
        if (strcmp(net, curr->destination) == 0) {
            if (tmp) {
                if (strcmp(curr->mask, tmp->mask) > 0) {
                    tmp = curr;
                }
            }
            else {
                tmp = curr;
            }
        }
        curr = curr->next;
    }
    return tmp;
}