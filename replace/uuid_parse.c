/*
 * uuid: emulation of e2fsprogs interface if implementation lacking.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Original uuid implementation: copyright (C) Theodore Ts'o
 *
 * This importation into heartbeat:
 *	Copyright (C) 2004 David Lee <t.d.lee@durham.ac.uk>
 *
 */

#include <crm_internal.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#include <string.h>
#include <ctype.h>

#include <replace_uuid.h>

/*
 * Local "replace" implementation of uuid functions.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

/* UUID Variant definitions */
#define UUID_VARIANT_NCS	0
#define UUID_VARIANT_DCE	1
#define UUID_VARIANT_MICROSOFT	2
#define UUID_VARIANT_OTHER	3

/* UUID Type definitions */
#define UUID_TYPE_DCE_TIME	1
#define UUID_TYPE_DCE_RANDOM	4

/* For uuid_compare() */
#define UUCMP(u1,u2) if (u1 != u2) return((u1 < u2) ? -1 : 1);

/************************************
 * Private types
 ************************************/

#define longlong long long

/*
 * Offset between 15-Oct-1582 and 1-Jan-70
 */
#define TIME_OFFSET_HIGH 0x01B21DD2
#define TIME_OFFSET_LOW  0x13814000

#if (SIZEOF_INT == 4)
typedef unsigned int __u32;
#elif (SIZEOF_LONG == 4)
typedef unsigned long __u32;
#endif

#if (SIZEOF_INT == 2)
typedef int __s16;
typedef unsigned int __u16;
#elif (SIZEOF_SHORT == 2)
typedef short __s16;
typedef unsigned short __u16;
#endif

typedef unsigned char __u8;

struct uuid {
    __u32 time_low;
    __u16 time_mid;
    __u16 time_hi_and_version;
    __u16 clock_seq;
    __u8 node[6];
};

/************************************
 * internal routines
 ************************************/
static void
uuid_pack(const struct uuid *uu, uuid_t ptr)
{
    __u32 tmp;
    unsigned char *out = ptr;

    tmp = uu->time_low;
    out[3] = (unsigned char)tmp;
    tmp >>= 8;
    out[2] = (unsigned char)tmp;
    tmp >>= 8;
    out[1] = (unsigned char)tmp;
    tmp >>= 8;
    out[0] = (unsigned char)tmp;

    tmp = uu->time_mid;
    out[5] = (unsigned char)tmp;
    tmp >>= 8;
    out[4] = (unsigned char)tmp;

    tmp = uu->time_hi_and_version;
    out[7] = (unsigned char)tmp;
    tmp >>= 8;
    out[6] = (unsigned char)tmp;

    tmp = uu->clock_seq;
    out[9] = (unsigned char)tmp;
    tmp >>= 8;
    out[8] = (unsigned char)tmp;

    memcpy(out + 10, uu->node, 6);
}

static void
uuid_unpack(const uuid_t in, struct uuid *uu)
{
    const __u8 *ptr = in;
    __u32 tmp;

    tmp = *ptr++;
    tmp = (tmp << 8) | *ptr++;
    tmp = (tmp << 8) | *ptr++;
    tmp = (tmp << 8) | *ptr++;
    uu->time_low = tmp;

    tmp = *ptr++;
    tmp = (tmp << 8) | *ptr++;
    uu->time_mid = tmp;

    tmp = *ptr++;
    tmp = (tmp << 8) | *ptr++;
    uu->time_hi_and_version = tmp;

    tmp = *ptr++;
    tmp = (tmp << 8) | *ptr++;
    uu->clock_seq = tmp;

    memcpy(uu->node, ptr, 6);
}

/************************************
 * Main routines, except uuid_generate*()
 ************************************/
void
uuid_clear(uuid_t uu)
{
    memset(uu, 0, 16);
}

int
uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
    struct uuid uuid1, uuid2;

    uuid_unpack(uu1, &uuid1);
    uuid_unpack(uu2, &uuid2);

    UUCMP(uuid1.time_low, uuid2.time_low);
    UUCMP(uuid1.time_mid, uuid2.time_mid);
    UUCMP(uuid1.time_hi_and_version, uuid2.time_hi_and_version);
    UUCMP(uuid1.clock_seq, uuid2.clock_seq);
    return memcmp(uuid1.node, uuid2.node, 6);
}

void
uuid_copy(uuid_t dst, const uuid_t src)
{
    unsigned char *cp1;
    const unsigned char *cp2;
    int i;

    for (i = 0, cp1 = dst, cp2 = src; i < 16; i++)
        *cp1++ = *cp2++;
}

/* if uu is the null uuid, return 1 else 0 */
int
uuid_is_null(const uuid_t uu)
{
    const unsigned char *cp;
    int i;

    for (i = 0, cp = uu; i < 16; i++)
        if (*cp++)
            return 0;
    return 1;
}

/* 36byte-string=>uuid */
int
uuid_parse(const char *in, uuid_t uu)
{
    struct uuid uuid;
    int i;
    const char *cp;
    char buf[3];

    if (strlen(in) != 36)
        return -1;
    for (i = 0, cp = in; i <= 36; i++, cp++) {
        if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
            if (*cp == '-')
                continue;
            else
                return -1;
        }
        if (i == 36)
            if (*cp == 0)
                continue;
        if (!isxdigit((int)*cp))
            return -1;
    }
    uuid.time_low = strtoul(in, NULL, 16);
    uuid.time_mid = strtoul(in + 9, NULL, 16);
    uuid.time_hi_and_version = strtoul(in + 14, NULL, 16);
    uuid.clock_seq = strtoul(in + 19, NULL, 16);
    cp = in + 24;
    buf[2] = 0;
    for (i = 0; i < 6; i++) {
        buf[0] = *cp++;
        buf[1] = *cp++;
        uuid.node[i] = strtoul(buf, NULL, 16);
    }

    uuid_pack(&uuid, uu);
    return 0;
}

/* uuid=>36byte-string-with-null */
void
uuid_unparse(const uuid_t uu, char *out)
{
    struct uuid uuid;

    uuid_unpack(uu, &uuid);
    sprintf(out,
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
            uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
            uuid.node[0], uuid.node[1], uuid.node[2], uuid.node[3], uuid.node[4], uuid.node[5]);
}

/************************************
 * Main routines: uuid_generate*()
 ************************************/

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
#  include <sys/sockio.h>
#endif
#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_SRANDOM
#  define srand(x) 	srandom(x)
#  define rand() 		random()
#endif

static int
get_random_fd(void)
{
    struct timeval tv;
    static int fd = -2;
    int i;

    if (fd == -2) {
        gettimeofday(&tv, 0);
        fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1)
            fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
        srand((getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);
    }
    /* Crank the random number generator a few times */
    gettimeofday(&tv, 0);
    for (i = (tv.tv_sec ^ tv.tv_usec) & 0x1F; i > 0; i--)
        rand();
    return fd;
}

/*
 * Generate a series of random bytes.  Use /dev/urandom if possible,
 * and if not, use srandom/random.
 */
static void
get_random_bytes(void *buf, int nbytes)
{
    int i, n = nbytes, fd = get_random_fd();
    int lose_counter = 0;
    unsigned char *cp = (unsigned char *)buf;

    if (fd >= 0) {
        while (n > 0) {
            i = read(fd, cp, n);
            if (i <= 0) {
                if (lose_counter++ > 16)
                    break;
                continue;
            }
            n -= i;
            cp += i;
            lose_counter = 0;
        }
    }

    /*
     * We do this all the time, but this is the only source of
     * randomness if /dev/random/urandom is out to lunch.
     */
    for (cp = buf, i = 0; i < nbytes; i++)
        *cp++ ^= (rand() >> 7) & 0xFF;
    return;
}

/*
 * Get the ethernet hardware address, if we can find it...
 */
static int
get_node_id(unsigned char *node_id)
{
#ifdef HAVE_NET_IF_H
    int sd;
    struct ifreq ifr, *ifrp;
    struct ifconf ifc;
    char buf[1024];
    int n, i;
    unsigned char *a;

/*
 * BSD 4.4 defines the size of an ifreq to be
 * max(sizeof(ifreq), sizeof(ifreq.ifr_name)+ifreq.ifr_addr.sa_len
 * However, under earlier systems, sa_len isn't present, so the size is 
 * just sizeof(struct ifreq)
 */
#  ifdef HAVE_SA_LEN
#    ifndef max
#      define max(a,b) ((a) > (b) ? (a) : (b))
#    endif
#    define ifreq_size(i) max(sizeof(struct ifreq),\
     sizeof((i).ifr_name)+(i).ifr_addr.sa_len)
#  else
#    define ifreq_size(i) sizeof(struct ifreq)
#  endif                        /* HAVE_SA_LEN */

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sd < 0) {
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0) {
        close(sd);
        return -1;
    }
    n = ifc.ifc_len;
    for (i = 0; i < n; i += ifreq_size(*ifr)) {
        ifrp = (struct ifreq *)((char *)ifc.ifc_buf + i);
        strncpy(ifr.ifr_name, ifrp->ifr_name, IFNAMSIZ);
#  ifdef SIOCGIFHWADDR
        if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
            continue;
        a = (unsigned char *)&ifr.ifr_hwaddr.sa_data;
#  else
#    ifdef SIOCGENADDR
        if (ioctl(sd, SIOCGENADDR, &ifr) < 0)
            continue;
        a = (unsigned char *)ifr.ifr_enaddr;
#    else
        /*
         * XXX we don't have a way of getting the hardware
         * address
         */
        close(sd);
        return 0;
#    endif                      /* SIOCGENADDR */
#  endif                        /* SIOCGIFHWADDR */
        if (!a[0] && !a[1] && !a[2] && !a[3] && !a[4] && !a[5])
            continue;
        if (node_id) {
            memcpy(node_id, a, 6);
            close(sd);
            return 1;
        }
    }
    close(sd);
#endif
    return 0;
}

/* Assume that the gettimeofday() has microsecond granularity */
#define MAX_ADJUSTMENT 10

static int
get_clock(__u32 * clock_high, __u32 * clock_low, __u16 * ret_clock_seq)
{
    static int adjustment = 0;
    static struct timeval last = { 0, 0 };
    static __u16 clock_seq;
    struct timeval tv;
    unsigned longlong clock_reg;

  try_again:
    gettimeofday(&tv, 0);
    if ((last.tv_sec == 0) && (last.tv_usec == 0)) {
        get_random_bytes(&clock_seq, sizeof(clock_seq));
        clock_seq &= 0x1FFF;
        last = tv;
        last.tv_sec--;
    }
    if ((tv.tv_sec < last.tv_sec) || ((tv.tv_sec == last.tv_sec) && (tv.tv_usec < last.tv_usec))) {
        clock_seq = (clock_seq + 1) & 0x1FFF;
        adjustment = 0;
        last = tv;
    } else if ((tv.tv_sec == last.tv_sec) && (tv.tv_usec == last.tv_usec)) {
        if (adjustment >= MAX_ADJUSTMENT)
            goto try_again;
        adjustment++;
    } else {
        adjustment = 0;
        last = tv;
    }

    clock_reg = tv.tv_usec * 10 + adjustment;
    clock_reg += ((unsigned longlong)tv.tv_sec) * 10000000;
    clock_reg += (((unsigned longlong)0x01B21DD2) << 32) + 0x13814000;

    *clock_high = clock_reg >> 32;
    *clock_low = clock_reg;
    *ret_clock_seq = clock_seq;
    return 0;
}

/* create a new uuid, based on randomness */
void
uuid_generate_random(uuid_t out)
{
    uuid_t buf;
    struct uuid uu;

    get_random_bytes(buf, sizeof(buf));
    uuid_unpack(buf, &uu);

    uu.clock_seq = (uu.clock_seq & 0x3FFF) | 0x8000;
    uu.time_hi_and_version = (uu.time_hi_and_version & 0x0FFF) | 0x4000;
    uuid_pack(&uu, out);
}

/* create a new uuid, based on time */
static void
uuid_generate_time(uuid_t out)
{
    static unsigned char node_id[6];
    static int has_init = 0;
    struct uuid uu;
    __u32 clock_mid;

    if (!has_init) {
        if (get_node_id(node_id) <= 0) {
            get_random_bytes(node_id, 6);
            /*
             * Set multicast bit, to prevent conflicts
             * with IEEE 802 addresses obtained from
             * network cards
             */
            node_id[0] |= 0x80;
        }
        has_init = 1;
    }
    get_clock(&clock_mid, &uu.time_low, &uu.clock_seq);
    uu.clock_seq |= 0x8000;
    uu.time_mid = (__u16) clock_mid;
    uu.time_hi_and_version = (clock_mid >> 16) | 0x1000;
    memcpy(uu.node, node_id, 6);
    uuid_pack(&uu, out);
}

void
uuid_generate(uuid_t out)
{
    if (get_random_fd() >= 0) {
        uuid_generate_random(out);
    } else {
        uuid_generate_time(out);
    }
}
