#ifndef SOCKETHELPER_H
#define SOCKETHELPER_H

#include <sockaddr_util.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#include <stunlib.h>

#define MAXBUFLEN 2048
#define MAX_LISTEN_SOCKETS 10


struct socketConfig{
    void *tInst;
    int sockfd;
    char* user;
    char* pass;
    char* realm;
};


struct listenConfig{
    struct socketConfig socketConfig[MAX_LISTEN_SOCKETS];
    int numSockets;
    /*Handles normal data like RTP etc */
    void (*data_handler)(struct socketConfig *, struct sockaddr *, 
                         void *, unsigned char *);
    /*Handles STUN packet*/
    void (*stun_handler)(struct socketConfig *, struct sockaddr *, 
                         void *, unsigned char *, int);
};

int createLocalUDPSocket(int ai_family,
                         const struct sockaddr *localIp,
                         uint16_t port);


int createSocket(char host[], char port[], 
                 int ai_flags, 
                 struct addrinfo *servinfo, 
                 struct addrinfo **p);

void *socketListenDemux(void *ptr);

void sendPacket(int sockHandle,
                const uint8_t *buf,
                int bufLen,
                const struct sockaddr *dstAddr,
                bool useRelay,
                uint8_t ttl);


#endif
