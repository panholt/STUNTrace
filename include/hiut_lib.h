#ifndef HIUT_LIB_H
#define HIUT_LIB_H

#define MAX_TTL 64

#include <stunlib.h>

struct hiutTTLinfo{
    //int ttl;
    //int messageSize;
    StunMsgId stunMsgId;
    
};

struct hiutPathElement{
    bool   gotAnswer;
    struct sockaddr_storage addr;
};

struct hiutResult{
    void *stunCtx;
    uint32_t currentTTL;
    uint32_t user_start_ttl;
    uint32_t user_max_ttl;
    uint32_t wait_ms;
    struct sockaddr_storage localAddr;
    struct sockaddr_storage remoteAddr;
    /* STUN Username and password */
    char *username;
    char *password;
    /* Initial Length of first STUN packet (TTL=1) */
    uint32_t stunLen;
    struct hiutPathElement pathElement[MAX_TTL];
    struct hiutTTLinfo ttlInfo[MAX_TTL];
    /* DISCUSS */
    DiscussData discuss;
};


#endif
