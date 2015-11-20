/*
** STUNTrace
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <string.h>

#include <stunlib.h>
#include <stunclient.h>
#include <stun_intern.h>

#include <npalib.h>

#include "utils.h"
#include "iphelper.h"
#include "sockethelper.h"
#include "hiut_lib.h"

int                        sockfd;
int                        icmpSocket;
static struct listenConfig listenConfig;
static char                rcv_message[MAXBUFLEN];

struct timeval start;
struct timeval stop;

pthread_mutex_t mutex;

char username[] = "evtj:h6vY\0";
char password[] = "VOkJxbRl1RmTxUk/WvJxBt\0";

#define max_iface_len 10

typedef enum {
  txt,
  json,
  csv
} OUTPUT_FORMAT;

OUTPUT_FORMAT out_format = txt;

struct trace_config {
  char                    interface[10];
  uint16_t                port;
  uint16_t                paralell;
  int32_t                 max_ttl;
  int32_t                 start_ttl;
  uint32_t                wait_ms;
  uint32_t                max_recuring;
  struct sockaddr_storage remoteAddr;
  struct sockaddr_storage localAddr;
};

void
handleStunRespIcmp(struct hiutResult* result,
                   int                ICMPtype,
                   int                ttl,
                   struct sockaddr*   srcAddr,
                   int                rtt,
                   int                retransmits);

void
handleStunNoAnswer(struct hiutResult* result);
void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData);

void
printResultLine(OUTPUT_FORMAT    format,
                bool             last,
                int              ttl,
                struct sockaddr* srcAddr,
                int              rtt,
                int              retransmits)
{
  char addr[SOCKADDR_MAX_STRLEN];

  if (format == txt)
  {
    printf(" %i %s %i.%ims (%i)", ttl,
           sockaddr_toString(srcAddr,
                             addr,
                             sizeof(addr),
                             false),
           rtt / 1000, rtt % 1000,
           retransmits);

      printf("\n");
  }
  else if (format == json)
  {
      printf( "           {\n");
      printf( "               \"hop\" : \"%i\",\n", ttl);
      printf( "               \"ip\"  : \"%s\",\n", sockaddr_toString(srcAddr,
                                                                    addr,
                                                                    sizeof(addr),
                                                                    false) );
      printf("               \"rtt\" : \"%i.%i\",\n",  rtt / 1000, rtt % 1000);
      printf("               \"retrans\" : \"%i\" \n", retransmits);
      printf("           }");
    if (!last)
    {
      printf(", \n");
    }
    else
    {
      printf("\n");
    }
  }
  else if (format == csv)
  {
      printf("%s,%i\n",sockaddr_toString(srcAddr,
                                       addr,
                                       sizeof(addr),
                                       false),
           ttl);
      printf( "%s,",sockaddr_toString(srcAddr,
                                    addr,
                                    sizeof(addr),
                                    false) );

  }


}

void
printTimeSpent(uint32_t wait)
{
  int             time;
  struct timespec timer;
  struct timespec remaining;

  timer.tv_sec  = 0;
  timer.tv_nsec = wait * 1000000;

  nanosleep(&timer, &remaining);


  gettimeofday(&stop, NULL);

  time =
    (stop.tv_sec * 1000000 +
     stop.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);
  if (out_format == json)
  {
      printf("        ],\n");
      printf("    \"time\" : \"%i.%i\"\n", time / 1000, time % 1000);
      printf("   }\n");
      printf("}\n");
  }
  else if (out_format == txt)
  {
      printf("Time spent: %i.%ims", time / 1000, time % 1000);
    if (wait > 0)
    {
      printf(" (wait: %ims)",       wait);
    }
      printf("\n");
  }
  else if (out_format == csv)
  {
    /* printf("slutt"); */
      printf("\n");
  }
}

void
printSegmentAnalytics(const struct npa_trace* trace)
{
  int                numseg = 3;
  struct npa_segment segments[numseg];
  npa_getSegmentRTTs(trace,
                     segments,
                     numseg);
  for (int i = 0; i < numseg; i++)
  {
    printf("Segment %i STT (%i->%i): %i.%ims \n",
           i + 1,
           segments[i].start,
           segments[i].stop,
           segments[i].stt / 1000,
           segments[i].stt % 1000);
  }
}

void
stopAndExit(struct hiutResult* result)
{


  if (result->num_traces < result->max_recuring)
  {
    printf("Finished Trace %i of %i\n", result->num_traces,
           result->max_recuring);

    for (int i = 0; i < MAX_TTL; i++)
    {
      result->pathElement[i].gotAnswer = false;
    }

    for (int i = 1; i < result->user_paralell_traces + 1; i++)
    {
      result->currentTTL = result->user_start_ttl - 1 + i;
      stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId, rand(),
                       i);
      StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                                 result,
                                 (struct sockaddr*)&result->remoteAddr,
                                 (struct sockaddr*)&result->localAddr,
                                 false,
                                 result->username,
                                 result->password,
                                 result->currentTTL,
                                 result->ttlInfo[result->currentTTL].stunMsgId,
                                 sockfd,
                                 sendPacket,
                                 StunStatusCallBack,
                                 NULL );
    }
  }
  else
  {
    printSegmentAnalytics(&result->trace);
    printTimeSpent(result->wait_ms);

    close(sockfd);
    exit(0);
  }
}


void
handleStunRespSucsessfull(struct hiutResult* result,
                          int                ttl,
                          struct sockaddr*   srcAddr,
                          struct sockaddr*   rflxAddr,
                          int                rtt,
                          int                retransmits)
{
  /* char addr[SOCKADDR_MAX_STRLEN]; */
  (void) rflxAddr;
  printResultLine(out_format,
                  true,
                  ttl,
                  srcAddr,
                  rtt,
                  retransmits);

  /* printf("   RFLX addr: '%s'\n", */
  /*       sockaddr_toString(rflxAddr, */
  /*                         addr, */
  /*                         sizeof(addr), */
  /*                         true)); */

  /*Got STUN response. We can stop now*/
  if ( sockaddr_sameAddr( (struct sockaddr*)&result->remoteAddr,srcAddr ) )
  {
    stopAndExit(0);
  }
  if (result->currentTTL < result->user_max_ttl)
  {
    result->currentTTL++;
    stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                     rand(), result->currentTTL);
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->ttlInfo[result->currentTTL].stunMsgId,
                               sockfd,
                               sendPacket,
                               StunStatusCallBack,
                               NULL );
  }

}


void
StunStatusCallBack(void*               userCtx,
                   StunCallBackData_T* stunCbData)
{
  /* char               addr[SOCKADDR_MAX_STRLEN]; */
  struct hiutResult* result = (struct hiutResult*)userCtx;

  if (result->pathElement[stunCbData->ttl].gotAnswer)
  {
    printf("Got his one already! Ignorin\n");
    return;
  }
  result->pathElement[stunCbData->ttl].gotAnswer = true;
  switch (stunCbData->stunResult)
  {
  case StunResult_BindOk:
    handleStunRespSucsessfull( (struct hiutResult*)userCtx,
                               stunCbData->ttl,
                               (struct sockaddr*)&stunCbData->srcAddr,
                               (struct sockaddr*)&stunCbData->rflxAddr,
                               stunCbData->rtt,
                               stunCbData->retransmits );
    break;
  case StunResult_ICMPResp:
    handleStunRespIcmp( (struct hiutResult*)userCtx,
                        stunCbData->ICMPtype,
                        stunCbData->ttl,
                        (struct sockaddr*)&stunCbData->srcAddr,
                        stunCbData->rtt,
                        stunCbData->retransmits );
    break;
  case StunResult_BindFailNoAnswer:
    handleStunNoAnswer( (struct hiutResult*)userCtx );
    break;
  default:
    printf("Should not happen (Probably a cancel OK)\n");
  }
}


void
handleStunNoAnswer(struct hiutResult* result)
{
  if (out_format == txt)
  {
    printf(" ? *\n");
  }
  else if (out_format == csv)
  {
    printf("*,?\n*,");
  }
  if (result->currentTTL < result->user_max_ttl)
  {
    result->currentTTL++;
    stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                     rand(), result->currentTTL);
    StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                               result,
                               (struct sockaddr*)&result->remoteAddr,
                               (struct sockaddr*)&result->localAddr,
                               false,
                               result->username,
                               result->password,
                               result->currentTTL,
                               result->ttlInfo[result->currentTTL].stunMsgId,
                               sockfd,
                               sendPacket,
                               StunStatusCallBack,
                               NULL );

  }
  else
  {
    printf("BBBB\n");
    stopAndExit(result);
  }
}

void
handleStunRespIcmp(struct hiutResult* result,
                   int                ICMPtype,
                   int                ttl,
                   struct sockaddr*   srcAddr,
                   int                rtt,
                   int                retransmits)
{


  if (ttl >= result->user_max_ttl)
  {
    printResultLine(out_format,
                    true,
                    ttl,
                    srcAddr,
                    rtt,
                    retransmits);

    npa_addHop(&result->trace,
               ttl,
               srcAddr,
               rtt);

    stopAndExit(result);
  }

  /* printf("Type: %i\n", ICMPtype); */
  if ( ( (ICMPtype == 11) && (srcAddr->sa_family == AF_INET) ) ||
       ( (ICMPtype == 3) && (srcAddr->sa_family == AF_INET6) ) )
  {
    if (result->currentTTL < result->user_max_ttl)
    {
      printResultLine(out_format,
                      false,
                      ttl,
                      srcAddr,
                      rtt,
                      retransmits);
      npa_addHop(&result->trace,
                 ttl,
                 srcAddr,
                 rtt);

      result->currentTTL++;
      stunlib_createId(&result->ttlInfo[result->currentTTL].stunMsgId,
                       rand(), result->currentTTL);
      StunClient_startSTUNTrace( (STUN_CLIENT_DATA*)result->stunCtx,
                                 result,
                                 (struct sockaddr*)&result->remoteAddr,
                                 (struct sockaddr*)&result->localAddr,
                                 false,
                                 result->username,
                                 result->password,
                                 result->currentTTL,
                                 result->ttlInfo[result->currentTTL].stunMsgId,
                                 sockfd,
                                 sendPacket,
                                 StunStatusCallBack,
                                 NULL );
    }
  }
  else if ( (ICMPtype == 3) && (srcAddr->sa_family == AF_INET) )
  {
    /*Got port unreachable. We can stop now*/

    if (result->path_max_ttl >= ttl)
    {
      printResultLine(out_format,
                      true,
                      ttl,
                      srcAddr,
                      rtt,
                      retransmits);

      npa_addHop(&result->trace,
                 ttl,
                 srcAddr,
                 rtt);

      result->path_max_ttl = ttl;
      /* cancel any outstanding transactions */
      for (int i = ttl + 1; i <= result->currentTTL; i++)
      {
        printf("Canceling transaction (%i)\n", i);
        StunClient_cancelBindingTransaction( (STUN_CLIENT_DATA*)result->stunCtx,
                                             result->ttlInfo[i].stunMsgId );
      }

      stopAndExit(result);
      result->num_traces++;
    }
  }
  else
  {
    printf("   Some sort of ICMP message. Ignoring\n");
  }
}

static void*
tickStun(void* ptr)
{
  struct timespec   timer;
  struct timespec   remaining;
  STUN_CLIENT_DATA* clientData = (STUN_CLIENT_DATA*)ptr;

  timer.tv_sec  = 0;
  timer.tv_nsec = 50000000;

  for (;; )
  {
    nanosleep(&timer, &remaining);
    StunClient_HandleTick(clientData, 50);
  }
}


void
stunHandler(struct socketConfig* config,
            struct sockaddr*     from_addr,
            void*                cb,
            unsigned char*       buf,
            int                  buflen)
{
  StunMessage       stunResponse;
  STUN_CLIENT_DATA* clientData = (STUN_CLIENT_DATA*)cb;
  char              realm[STUN_MSG_MAX_REALM_LENGTH];

  if ( stunlib_DecodeMessage(buf, buflen, &stunResponse, NULL, NULL) )
  {
    if (stunResponse.msgHdr.msgType == STUN_MSG_DataIndicationMsg)
    {
      if (stunResponse.hasData)
      {
        /* Decode and do something with the data? */
        /* config->data_handler(config->socketConfig[i].sockfd, */
        /*                     config->socketConfig[i].tInst, */
        /*                     &buf[stunResponse.data.offset]); */
      }
    }
    if (stunResponse.hasRealm)
    {
      memcpy(&realm, stunResponse.realm.value, STUN_MSG_MAX_REALM_LENGTH);
    }
    if (stunResponse.hasMessageIntegrity)
    {
      if ( stunlib_checkIntegrity( buf,
                                   buflen,
                                   &stunResponse,
                                   (uint8_t*)config->pass,
                                   strlen(config->pass) ) )
      {
        /* printf("     - Integrity check OK\n"); */
      }
      else
      {
        /* printf("     - Integrity check NOT OK\n"); */
      }
    }
    StunClient_HandleIncResp(clientData,
                             &stunResponse,
                             from_addr);
  }
}


void
dataHandler(struct socketConfig* config,
            struct sockaddr*     fromAddr,
            void*                cb,
            unsigned char*       message)
{
  struct hiutResult*      result;
  struct sockaddr_storage dst_addr;
  char                    dst_str[INET6_ADDRSTRLEN];

  int n = sizeof(rcv_message);

  memcpy(rcv_message, message, n);
  if (n > 0)
  {
    rcv_message[n - 1] = '\0';
  }
  if (config->sockfd == icmpSocket)
  {
    /* is it a icmp message? At least on the right handle. */
    result = (struct hiutResult*)cb;
    if (result->localAddr.ss_family == AF_INET)
    {
      struct ip*   ip_packet, * inner_ip_packet;
      struct icmp* icmp_packet;
      ip_packet   = (struct ip*) &rcv_message;
      icmp_packet =
        (struct icmp*) ( rcv_message + (ip_packet->ip_hl << 2) );
      inner_ip_packet = &icmp_packet->icmp_ip;

      sockaddr_initFromIPv4String( (struct sockaddr_in*)&dst_addr,
                                   inet_ntop(AF_INET, &ip_packet->ip_dst,
                                             dst_str,INET_ADDRSTRLEN) );

      if ( sockaddr_sameAddr( (struct sockaddr*)&dst_addr,
                              (struct sockaddr*)&result->localAddr ) )
      {
        int ttl = (inner_ip_packet->ip_len - result->stunLen - 24) / 4;

        /* Check if the length field in the ICMP header is set to something */
        /* Todo Fix lengths. */
        if ( (ntohs(icmp_packet->icmp_id) > 20) &&
             (ntohs(icmp_packet->icmp_id) < 1024) )
        {
          /* Check if it is a STUN packet */
          if ( stunlib_isStunMsg(message + 56, n - 56) )
          {
            stunHandler(config,
                        fromAddr,
                        (STUN_CLIENT_DATA*)result->stunCtx,
                        message + 56,
                        n - 56);
            return;
          }
        }
        StunClient_HandleICMP( (STUN_CLIENT_DATA*)result->stunCtx,
                               result->ttlInfo[ttl].stunMsgId,
                               fromAddr,
                               icmp_packet->icmp_type,
                               ttl );

      }
      else
      {
        printf("Not for me..\n");
      }
    }
    else
    {
      int32_t           ttl_v6;
      uint16_t          paylen;
      uint32_t          stunlen;
      struct ip6_hdr*   inner_ip_hdr;
      struct icmp6_hdr* icmp_hdr;
      icmp_hdr     = (struct icmp6_hdr*) &rcv_message;
      inner_ip_hdr = (struct ip6_hdr*)&rcv_message[8];

      paylen  = ntohs(inner_ip_hdr->ip6_plen);
      stunlen = result->stunLen + 4;

      /*FIX me*/
      if (icmp_hdr->icmp6_type != 3)
      {
        return;
      }

      ttl_v6 = (paylen - stunlen) / 4;
      StunClient_HandleICMP( (STUN_CLIENT_DATA*)result->stunCtx,
                             result->ttlInfo[ttl_v6].stunMsgId,
                             fromAddr,
                             icmp_hdr->icmp6_type,
                             ttl_v6 );
    }
  }
}

static void
teardown()
{
  close(sockfd);
  exit(0);
}


void
printUsage()
{
  printf("Usage: nptrace [options] host\n");
  printf("Options: \n");
  printf("  -i, --interface               Interface\n");
  printf("  -p, --port                    Destination port\n");
  printf("  -j [N],  --jobs [N]           Allow N transactions at once\n");
  printf("  -m [ttl], --max_ttl [ttl]     Max value for TTL\n");
  printf("  -M [ttl], --start_ttl [ttl]   Start at ttl value\n");
  printf("  -w [ms], --waittime [ms]      Wait ms for ICMP response\n");
  printf(
    "  -r [N], --recuring [N]        Number of recuring traces before stopping\n");
  printf("  -x, --json                    Output in JSON format\n");
  printf("  -c, --csv                     Output in JSON format\n");
  printf("  -v, --version                 Prints version number\n");
  printf("  -h, --help                    Print help text\n");
  exit(0);

}

int
main(int   argc,
     char* argv[])
{
  pthread_t         stunTickThread;
  pthread_t         socketListenThread;
  struct hiutResult result;

  STUN_CLIENT_DATA* clientData;
  char              addrStr[SOCKADDR_MAX_STRLEN];

  struct trace_config config;
  int                 c;
  /* int                 digit_optind = 0; */
  int i;
  /* set config to default values */
  strncpy(config.interface, "default", 7);
  config.port         = 3478;
  config.paralell     = 4;
  config.max_ttl      = 32;
  config.start_ttl    = 1;
  config.max_ttl      = 255;
  config.wait_ms      = 0;
  config.max_recuring = 1;

  static struct option long_options[] = {
    {"interface", 1, 0, 'i'},
    {"port", 1, 0, 'p'},
    {"jobs", 1, 0, 'j'},
    {"max_ttl", 1, 0, 'm'},
    {"start_ttl", 1, 0, 'M'},
    {"waittime", 1, 0, 'w'},
    {"recuring", 1, 0, 'r'},
    {"json", 0, 0, 'x'},
    {"csv", 0, 0, 'c'},
    {"help", 0, 0, 'h'},
    {"version", 0, 0, 'v'},
    {NULL, 0, NULL, 0}
  };
  if (argc < 2)
  {
    printUsage();
    exit(0);
  }
  int option_index = 0;
  while ( ( c = getopt_long(argc, argv, "hvi:p:j:m:M:w:r:",
                            long_options, &option_index) ) != -1 )
  {
    /* int this_option_optind = optind ? optind : 1; */
    switch (c)
    {

    case 'x':
      out_format = json;
      break;
    case 'c':
      out_format = csv;
      break;
    case 'i':
      strncpy(config.interface, optarg, max_iface_len);
      break;
    case 'p':
      config.port = atoi(optarg);
      break;
    case 'j':
      config.paralell = atoi(optarg);
      break;
    case 'm':
      config.max_ttl = atoi(optarg);
      break;
    case 'M':
      config.start_ttl = atoi(optarg);
      break;
    case 'w':
      config.wait_ms = atoi(optarg);
      break;
    case 'r':
      config.max_recuring = atoi(optarg);
      break;
    case 'h':
      printUsage();
      break;
    case 'v':
      printf("Version 0.1\n");
      exit(0);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  if (optind < argc)
  {
    if ( !getRemoteIpAddr( (struct sockaddr*)&config.remoteAddr,
                           argv[optind++],
                           config.port ) )
    {
      printf("Error getting remote IPaddr");
      exit(1);
    }
  }


  if ( !getLocalInterFaceAddrs( (struct sockaddr*)&config.localAddr,
                                config.interface,
                                config.remoteAddr.ss_family,
                                IPv6_ADDR_NORMAL,
                                false ) )
  {
    printf("Error getting IPaddr on %s\n", config.interface);
    exit(1);
  }


  /* Setting up UDP socket and and aICMP sockhandle */
  sockfd = createLocalUDPSocket(config.remoteAddr.ss_family,
                                (struct sockaddr*)&config.localAddr,
                                0);

  if (config.remoteAddr.ss_family == AF_INET)
  {
    icmpSocket = socket(config.remoteAddr.ss_family, SOCK_DGRAM, IPPROTO_ICMP);
  }
  else
  {
    icmpSocket =
      socket(config.remoteAddr.ss_family, SOCK_DGRAM, IPPROTO_ICMPV6);
  }

  if (icmpSocket < 0)
  {
    perror("socket");
    exit(1);
  }

  signal(SIGINT, teardown);
  StunClient_Alloc(&clientData);

  memset( &result, 0, sizeof(result) );

  listenConfig.socketConfig[0].tInst  = clientData;
  listenConfig.socketConfig[0].sockfd = sockfd;
  listenConfig.socketConfig[0].user   = username;
  listenConfig.socketConfig[0].pass   = password;
  listenConfig.stun_handler           = stunHandler;


  listenConfig.socketConfig[1].tInst  = &result;
  listenConfig.socketConfig[1].sockfd = icmpSocket;
  listenConfig.socketConfig[1].user   = NULL;
  listenConfig.socketConfig[1].pass   = NULL;
  listenConfig.numSockets             = 2;
  listenConfig.data_handler           = dataHandler;



  pthread_create(&stunTickThread, NULL, tickStun, (void*)clientData);
  pthread_create(&socketListenThread,
                 NULL,
                 socketListenDemux,
                 (void*)&listenConfig);

  /* Fill inn the hiut struct so we get something back in the CB */
  sockaddr_copy( (struct sockaddr*)&result.localAddr,
                 (struct sockaddr*)&config.localAddr );
  sockaddr_copy( (struct sockaddr*)&result.remoteAddr,
                 (struct sockaddr*)&config.remoteAddr );
  result.username             = username;
  result.password             = password;
  result.user_max_ttl         = config.max_ttl;
  result.user_start_ttl       = config.start_ttl;
  result.wait_ms              = config.wait_ms;
  result.max_recuring         = config.max_recuring;
  result.user_paralell_traces = config.paralell;
  result.path_max_ttl         = 255;
  result.num_traces           = 1;

  npa_init(&result.trace);
  srand( time(NULL) ); /* Initialise the random seed. */

  /* *starting here.. */
  if (out_format == json)
  {
    printf( "{\n");
    printf( "  \"stuntrace\" : {\n");
    printf( "       \"src\" : \"%s\",\n",
            sockaddr_toString( (struct sockaddr*)&config.localAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );

    printf( "       \"dest\" : \"%s\",\n",
            sockaddr_toString( (struct sockaddr*)&config.remoteAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );
    printf("       \"nodes\" : [\n");

  }
  else if (out_format == txt)
  {
    printf( "Starting stuntrace from: '%s'",
            sockaddr_toString( (struct sockaddr*)&config.localAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );

    printf( "to: '%s'\n",
            sockaddr_toString( (struct sockaddr*)&config.remoteAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );
  }
  else if (out_format == csv)
  {
    printf( "%s,",
            sockaddr_toString( (struct sockaddr*)&config.localAddr,
                               addrStr,
                               sizeof(addrStr),
                               false ) );
  }

  gettimeofday(&start, NULL);

  for (i = 1; i < config.paralell + 1; i++)
  {
    uint32_t len;
    stunlib_createId(&result.ttlInfo[i].stunMsgId, rand(), i);
    result.stunCtx    = clientData;
    result.currentTTL = config.start_ttl - 1 + i;


    len = StunClient_startSTUNTrace(clientData,
                                    &result,
                                    (struct sockaddr*)&result.remoteAddr,
                                    (struct sockaddr*)&result.localAddr,
                                    false,
                                    result.username,
                                    result.password,
                                    result.currentTTL,
                                    result.ttlInfo[result.currentTTL].stunMsgId,
                                    sockfd,
                                    sendPacket,
                                    StunStatusCallBack,
                                    NULL);
    if (i == 1)
    {
      result.stunLen = len;
    }
  }

  pause();
}
