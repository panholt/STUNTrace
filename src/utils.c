

#include <stdio.h>
#include <stdlib.h>
#include <stunlib.h>
#include <time.h>
#include <string.h>
#include "utils.h"


typedef struct {
    uint64_t  ms64;
    uint64_t  ls64;
} _uint128_t;

typedef union {
    _uint128_t   ui128;
    uint8_t            ba[ 16];
} ui128byteArray_t;


uint64_t random64(void);
_uint128_t random128(void);


uint64_t random64(void)
{
    uint64_t p2 = ((uint64_t)rand() << 62) & 0xc000000000000000LL;
    uint64_t p1 = ((uint64_t)rand() << 31) & 0x3fffffff80000000LL;
    uint64_t p0 = ((uint64_t)rand() <<  0) & 0x000000007fffffffLL;

    return p2 | p1 | p0;
}


_uint128_t random128(void)
{
    _uint128_t  result;

    result.ms64 = random64();
    result.ls64 = random64();

    return result;
}


StunMsgId generateTransactionId(void)
{
    StunMsgId           tId;
    ui128byteArray_t    ui128byteArray;

    srand(time(NULL)); // Initialise the random seed.

    ui128byteArray.ui128 = random128();

    memcpy(&tId.octet[ 0], &ui128byteArray.ba[ 0], STUN_MSG_ID_SIZE);

    return tId;
}

