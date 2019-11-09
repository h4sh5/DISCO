/***************************************************************************

    disco.h - Disco header file

    Date: 06.12.2003
    Ver : 1.2

    Disco: The passive ip discovery and fingerprinting tool

    Copyright (c) 2003 by Preston Wood
    All rights reserved.

    Author(s): Preston Wood  <p@altmode.com>

/***************************************************************************

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
  THE AUTHOR, OR ANY OTHER CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

***************************************************************************/

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
//#include <netinet/ip.h>
//#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define SNAPLEN         74
#define PROMISC         1
#define TIMEOUT         500
#define FILTER          "ip"
#define SYNCHAR		"S"
#define SYNACKCHAR	"A"
#define HASH_TABLE_SIZE 19999
#define MAXFP           5000

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

#define EXTRACT_BIT(p) \
        ((u_short)*((u_char *)(p) + 0))


#define EXTRACT_16BITS(p) \
        ((u_short)*((u_char *)(p) + 0) << 8 | \
        (u_short)*((u_char *)(p) + 1))

#define EXTRACT_24BITS(p) \
        ((u_short)*((u_char *)(p) + 0) << 8 | \
        (u_short)*((u_char *)(p) + 1) << 8 | \
        (u_short)*((u_char *)(p) + 2))
        
#define IP_DF   0x4000  /* dont fragment flag */
#define IP_MF   0x2000  /* more fragments flag */

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

#define targsize 255

#define MAX_STR_LEN  2048
#define MAX_NUM_ARGS 32

#ifdef _SUN_
typedef   unsigned char u_int8_t;
typedef   unsigned int u_int32_t;
#endif

struct table_entry
{
    uint32_t uip;
    struct table_entry *next;
};

struct fingerprints
{
    int       win;
    int       ttl;
    u_int32_t mss;
    u_int8_t  df;
    int       wscale;
    u_int16_t sackok;
    u_int8_t  nop;
    u_int16_t psize;
    char      packet_type[1]; //SYN or SYNACK (S or A)
    char      *os;
};

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };


struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};



char *iprintf(u_char *);
int packet_to_check(uint32_t, struct table_entry **);
char fingerprint_packet(u_char *);
int load_fingerprints();
int packet_dup_check(uint32_t, struct table_entry **, uint32_t);
int packet_add_entry(uint32_t, struct table_entry **, uint32_t);
uint32_t packet_hash(uint32_t);
void ht_init_table(struct table_entry **);
void cleanup(int);
int catch_sig(int, void(*)());
void usage(char *);



/** parse()
 *
 * Converts the given string into an array of arguments
 *
 * \param  buf Pointer to a character array containing
 *             whitespace-delimited arguments
 * \param  args Pointer to an array of character arrays
 *
 * \return 1 on success, 0 on failure
 */

int parse(char *, char **);

/** pipe_out()
 *
 * Pipes the given string to the given program
 *
 * \param  pre Pointer to a character array containing the pretext (-P)
 * \param  str Pointer to a character array containing the string
 *             to output
 * \param  args Pointer to an array of arguments, index 0 being the
 *              program to fork / exec
 *
 * \return 1 on success, 0 on failure
 */

int pipe_out(char *, char *, char **);



/* EOF */
