/*
** STUNTrace
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
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
#include <ctype.h>

#include <stunlib.h>
#include <stunclient.h>
#include <stuntrace.h>
#include <stun_intern.h>

#include <palib.h>
#include <json_output.h>

#include <uuid/uuid.h>

#include <cassandra.h>

#include "utils.h"
#include "iphelper.h"
#include "sockethelper.h"
#include "ip_query.h"
#include "version.h"

int                        sockfd;
int                        icmpSocket;
int                        querySocket;
static struct listenConfig listenConfig;
struct timeval             start;
struct timeval             stop;
bool                       doASLookup;

pthread_mutex_t mutex;

char username[] = "evtj:h6vY\0";
char password[] = "VOkJxbRl1RmTxUk/WvJxBt\0";
char uuid_str[37];
#define max_iface_len 10

typedef enum {
  txt,
  json,
  csv
} OUTPUT_FORMAT;

OUTPUT_FORMAT out_format = txt;

struct trace_config {
  char     interface[10];
  uint16_t port;
  uint16_t paralell;
  int32_t  max_ttl;
  int32_t  start_ttl;
  uint32_t wait_ms;
  uint32_t max_recuring;
  bool     debug;
  bool     as_lookup;
  /* struct sockaddr_storage remoteAddr; */
  /* struct sockaddr_storage localAddr; */
  struct pa_trace trace;
  bool            use_cassandra;
  char            cassandra_fqdn[255];
};


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

  printf("Time spent: %i.%ims", time / 1000, time % 1000);
  if (wait > 0)
  {
    printf(" (wait: %ims)", wait);
  }
  printf("\n");

}

void
printSegmentAnalytics(const struct pa_trace* trace)
{
  int               numseg = 15;
  struct pa_segment segments[numseg];
  numseg = pa_getSegmentAsRTTs(trace,
                               segments,
                               numseg);

  printf( "------- Path Stats ------\n");
  printf( "hops: %i, samples: %i, inactive: %i (of %i)\n",
          pa_getNumberOfHops(trace),
          pa_getNumberOfSamples(trace),
          pa_getNumberOfInactiveHops(trace),
          pa_getNumberOfHops(trace) );

  for (int i = 0; i < numseg; i++)
  {
    if (segments[i].type == PA_SEGMENT_INTRA_AS)
    {
      printf("Segment %i Time spent in AS: %i (Hop:%i->%i): %i.%ims \n",
             i + 1,
             trace->hop[segments[i].start].as,
             segments[i].start,
             segments[i].stop,
             segments[i].stt / 1000,
             segments[i].stt % 1000);
    }
    if (segments[i].type == PA_SEGMENT_INTER_AS)
    {
      printf("Segment %i Time spent between AS%i -> AS%i: %i.%ims \n",
             i + 1,
             trace->hop[segments[i].start].as,
             trace->hop[segments[i].stop].as,
             segments[i].stt / 1000,
             segments[i].stt % 1000);
    }

  }
}

void
postToCasandra(const char*            fqdn,
               const struct pa_trace* trace)
{
  /* Setup and connect to cluster */
  CassFuture*  connect_future = NULL;
  CassCluster* cluster        = cass_cluster_new();
  CassSession* session        = cass_session_new();

  /* Add contact points */
  cass_cluster_set_contact_points(cluster, fqdn);
  cass_cluster_set_whitelist_filtering(cluster,
                                       fqdn);

  /* Provide the cluster object as configuration to connect the session */
  connect_future = cass_session_connect(session, cluster);

  if (cass_future_error_code(connect_future) == CASS_OK)
  {
    CassFuture* close_future = NULL;

    /* Build statement and execute query */
    /* const char* query = "SELECT keyspace_name " */
    /*                    "FROM system.schema_keyspaces;"; */
    size_t numNodes = pa_getNumberOfHops(trace);
    for (size_t i = 1; i <= numNodes; i++)
    {
      char query[4096];
      strncpy(query, "INSERT INTO stuntrace.pathtrace JSON '", sizeof query);
      palib_traceToJsonTableEntry(query,
                                  i,
                                  trace,
                                  sizeof(query) - strlen(query) - 1);
      strncat(query, "}';", sizeof(query) - strlen(query) - 1);

      CassStatement* statement = cass_statement_new(query, 0);

      CassFuture* result_future = cass_session_execute(session, statement);

      if (cass_future_error_code(result_future) == CASS_OK)
      {
        /* Retrieve result set and iterate over the rows */
        /* printf("Inserted into db.. I think...\n"); */
        /* cass_result_free(result); */
        /* cass_iterator_free(rows); */
      }
      else
      {
        /* Handle error */
        const char* message;
        size_t      message_length;
        cass_future_error_message(result_future, &message, &message_length);
        fprintf(stderr, "Unable to run query: '%.*s'\n", (int)message_length,
                message);
      }

      cass_statement_free(statement);
      cass_future_free(result_future);
    }
    /* Close the session */
    close_future = cass_session_close(session);
    cass_future_wait(close_future);
    cass_future_free(close_future);
    printf("Results posted to Cassandra\n");
  }
  else
  {
    /* Handle error */
    const char* message;
    size_t      message_length;
    cass_future_error_message(connect_future, &message, &message_length);
    fprintf(stderr, "Unable to connect: '%.*s'\n", (int)message_length,
            message);
  }

  cass_future_free(connect_future);
  cass_cluster_free(cluster);
  cass_session_free(session);

}

void
StunTraceCallBack(void*                    userCtx,
                  StunTraceCallBackData_T* data)
{
  struct trace_config* config = (struct trace_config*) userCtx;
  struct pa_trace*     trace  = &config->trace;
  char                 addr[SOCKADDR_MAX_STRLEN];
  int                  asnum = 0;
  if (data->nodeAddr == NULL)
  {
    /* pa_addHop(trace, data->hop, data->nodeAddr, data->rtt); */
    printf(" %i * \n", data->hop);
  }
  else
  {
    sockaddr_toString(data->nodeAddr,
                      addr,
                      sizeof(addr),
                      false);

    pa_addHop(trace, data->hop, data->nodeAddr, data->rtt);
    if (data->trace_num <= 1)
    {
      if (doASLookup)
      {
        asnum = asLookup(addr);
        pa_addIpInfo(trace, data->nodeAddr, asnum);
      }
    }
    printf(" %i %s %i.%ims (%i)  (AS:%i)\n", data->hop,
           addr,
           data->rtt / 1000, data->rtt % 1000,
           data->retransmits,
           asnum);
  }
  if (data->traceEnd)
  {
    printSegmentAnalytics(trace);

    if (data->done)
    {
      /* Post to db */
      if (config->use_cassandra)
      {
        postToCasandra(config->cassandra_fqdn, trace);
      }

      printTimeSpent(0);
      exit(0);
    }
  }
}



void
stundbg(void*              ctx,
        StunInfoCategory_T category,
        char*              errStr)
{
  (void) category;
  (void) ctx;
  printf("%s\n", errStr);
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
  return NULL;
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

icmpHandler(struct socketConfig* config,
            struct sockaddr*     fromAddr,
            void*                cb,
            int                  icmpType)
{
  (void)config;
  StunClient_HandleICMP( (STUN_CLIENT_DATA*)cb,
                         fromAddr,
                         icmpType );

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
  printf("  -l, --as                      Enable AS number lookup\n");
  printf("  -v, --version                 Prints version number\n");
  printf("  -h, --help                    Print help text\n");
  exit(0);

}



int
main(int   argc,
     char* argv[])
{
  pthread_t stunTickThread;
  pthread_t socketListenThread;

  STUN_CLIENT_DATA* clientData;
  char              addrStr[SOCKADDR_MAX_STRLEN];
  /* generate */
  uuid_t uuid;
  uuid_generate(uuid);
  uuid_unparse_lower(uuid, uuid_str);

  struct trace_config config;
  pa_init(&config.trace, uuid_str);
  int c;
  /* int                 digit_optind = 0; */
  /* set config to default values */
  strncpy(config.interface, "default", 7);
  config.port         = 3478;
  config.paralell     = 4;
  config.max_ttl      = 32;
  config.start_ttl    = 1;
  config.max_ttl      = 255;
  config.wait_ms      = 0;
  config.max_recuring = 1;
  config.as_lookup    = false;
  config.debug        = false;

  static struct option long_options[] = {
    {"interface", 1, 0, 'i'},
    {"port", 1, 0, 'p'},
    {"jobs", 1, 0, 'j'},
    {"max_ttl", 1, 0, 'm'},
    {"start_ttl", 1, 0, 'M'},
    {"waittime", 1, 0, 'w'},
    {"recuring", 1, 0, 'r'},
    {"as", 0, 0, 'l'},
    {"debug", 0, 0, 'd'},
    {"cassandra", 1, 0, '3'},
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
  while ( ( c = getopt_long(argc, argv, "hvdli:p:j:m:M:w:r:",
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
    case 'd':
      config.debug = true;
      break;
    case 'l':
      config.as_lookup = true;
      break;
    case '3':
      if (optarg)
      {
        config.use_cassandra = true;
      }
      strncpy(config.cassandra_fqdn, optarg, 255);
      break;

    case 'h':
      printUsage();
      break;
    case 'v':
      printf("Version %s\n", VERSION_SHORT);
      exit(0);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  if (optind < argc)
  {
    if ( !getRemoteIpAddr( (struct sockaddr*)&config.trace.to_addr,
                           argv[optind++],
                           config.port ) )
    {
      printf("Error getting remote IPaddr");
      exit(1);
    }
  }
  doASLookup = config.as_lookup;

  if ( !getLocalInterFaceAddrs( (struct sockaddr*)&config.trace.from_addr,
                                config.interface,
                                config.trace.to_addr.ss_family,
                                IPv6_ADDR_NORMAL,
                                false ) )
  {
    printf("Error getting IPaddr on %s\n", config.interface);
    exit(1);
  }

  StunClient_Alloc(&clientData);
  /* Setting up UDP socket and and aICMP sockhandle */
  sockfd = createLocalSocket(config.trace.to_addr.ss_family,
                             (struct sockaddr*)&config.trace.from_addr,
                             SOCK_DGRAM,
                             0);
  listenConfig.tInst                  = clientData;
  listenConfig.socketConfig[0].sockfd = sockfd;
  listenConfig.socketConfig[0].user   = username;
  listenConfig.socketConfig[0].pass   = password;
  listenConfig.stun_handler           = stunHandler;
  listenConfig.icmp_handler           = icmpHandler;
  listenConfig.numSockets             = 1;
  #if defined(__linux)
  int val = 1;
  if (setsockopt( sockfd, SOL_IP, IP_RECVERR, &val, sizeof (val) ) < 0)
  {
    perror("setsockopt IP_RECVERR");
    exit(1);
  }
  #else
  if (config.trace.to_addr.ss_family == AF_INET)
  {
    icmpSocket =
      socket(config.trace.to_addr.ss_family, SOCK_DGRAM, IPPROTO_ICMP);
  }
  else
  {
    icmpSocket =
      socket(config.trace.to_addr.ss_family, SOCK_DGRAM, IPPROTO_ICMPV6);
  }

  if (icmpSocket < 0)
  {

    perror("socket");
    exit(1);

  }

  listenConfig.socketConfig[1].sockfd = icmpSocket;
  listenConfig.socketConfig[1].user   = NULL;
  listenConfig.socketConfig[1].pass   = NULL;
  listenConfig.numSockets             = 2;

  #endif
  signal(SIGINT, teardown);


  if (config.debug)
  {
    printf("registering logger\n");
    StunClient_RegisterLogger(clientData,
                              stundbg,
                              clientData);
  }
  pthread_create(&stunTickThread, NULL, tickStun, (void*)clientData);
  pthread_create(&socketListenThread,
                 NULL,
                 socketListenDemux,
                 (void*)&listenConfig);


  /* pa_init(&result.trace); */
  srand( time(NULL) ); /* Initialise the random seed. */



  /* printf("AS: %i\n", asLookup("192.168.10.12")); */



  /* *starting here.. */

  printf( "Starting stuntrace from: '%s'",
          sockaddr_toString( (struct sockaddr*)&config.trace.from_addr,
                             addrStr,
                             sizeof(addrStr),
                             true ) );

  printf( "to: '%s'\n",
          sockaddr_toString( (struct sockaddr*)&config.trace.to_addr,
                             addrStr,
                             sizeof(addrStr),
                             true ) );
  printf(" UUID: %s\n", uuid_str);

  gettimeofday(&start, NULL);


  pa_addTimestamp(&config.trace, &start);

/* #if 0 */
  int len = StunTrace_startTrace(clientData,
                                 &config,
                                 (const struct sockaddr*)&config.trace.to_addr,
                                 (const struct sockaddr*)&config.trace.from_addr,
                                 sockfd,
                                 username,
                                 password,
                                 config.max_recuring,
                                 StunTraceCallBack,
                                 sendPacket);

  listenConfig.socketConfig[1].firstPktLen = len;
/* #endif */
/* sleep(100); */
/* exit(0); */
  pause();
}
