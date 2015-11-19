#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pthread.h>

#include <stdbool.h>

#include <stunlib.h>
#include <stunclient.h>
#include "sockethelper.h"
#include "utils.h"

#define MYPORT "3478"    // the port users will be connecting to
#define PASSWORD "VOkJxbRl1RmTxUk/WvJxBt"

int sockfd;


void teardown()
{
  close(sockfd);
  printf("Quitting...\n");
  exit(0);
}


void stunHandler(struct socketConfig *config, struct sockaddr *from_addr, void *cb, unsigned char *buf, int buflen)
{
    StunMessage stunRequest;
    STUN_INCOMING_REQ_DATA pReq;
    STUN_CLIENT_DATA *clientData = (STUN_CLIENT_DATA *)cb;
    char realm[STUN_MSG_MAX_REALM_LENGTH];

    printf("Got a STUN message... (%i)\n", buflen);
    stunlib_DecodeMessage(buf, buflen, &stunRequest, NULL, stdout);
    printf("Finished decoding..\n");
    if (stunRequest.msgHdr.msgType == STUN_MSG_DataIndicationMsg) {
        if (stunRequest.hasData) {
            //Decode and do something with the data?
            //config->data_handler(config->socketConfig[i].sockfd,
            //                     config->socketConfig[i].tInst,
            //                     &buf[stunResponse.data.offset]);
        }
    }
    if (stunRequest.hasRealm) {
        memcpy(&realm, stunRequest.realm.value, STUN_MSG_MAX_REALM_LENGTH);
    }

    if (stunRequest.hasMessageIntegrity) {
        printf("Checking integrity..%s\n", config->pass);
        if (stunlib_checkIntegrity(buf,
                                   buflen,
                                   &stunRequest,
                                   (uint8_t*)config->pass,
                                   strlen(config->pass))) {
            printf("     - Integrity check OK\n");
        } else {
            printf("     - Integrity check NOT OK\n");
        }
    }

    StunServer_HandleStunIncomingBindReqMsg(config->tInst,
                                            &pReq,
                                            &stunRequest,
                                            false);

    StunServer_SendConnectivityBindingResp(config->tInst,
                                           config->sockfd,
                                           stunRequest.msgHdr.id,
                                           PASSWORD,
                                           from_addr,
                                           from_addr,
                                           NULL,
                                           sendPacket,
                                           false,
                                           200,
                                           NULL);

}



int main(void)
{
    struct addrinfo *servinfo, *p;
    int numbytes;
    struct sockaddr_storage their_addr;
    unsigned char buf[MAXBUFLEN];

    StunMessage stunRequest;
    STUN_INCOMING_REQ_DATA pReq;

    pthread_t socketListenThread;

    STUN_CLIENT_DATA *clientData;
    struct listenConfig listenConfig;

    StunClient_Alloc(&clientData);

    signal(SIGINT, teardown);

    sockfd = createSocket(NULL, MYPORT, AI_PASSIVE, servinfo, &p);

    listenConfig.socketConfig[0].tInst = clientData;
    listenConfig.socketConfig[0].sockfd= sockfd;
    listenConfig.socketConfig[0].user = NULL;
    listenConfig.socketConfig[0].pass = PASSWORD;
    listenConfig.stun_handler = stunHandler;
    listenConfig.numSockets = 1;



    pthread_create( &socketListenThread, NULL, socketListenDemux, (void*)&listenConfig);

    while(1) {
        printf("stunserver: waiting to recvfrom...\n");

        sleep(1000);
    }
}
