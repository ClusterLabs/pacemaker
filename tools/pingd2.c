
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/un.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <sys/socket.h>
#include <sys/uio.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/lsb_exitcodes.h>

typedef struct ping_node_s {
        int    			fd;		/* ping socket */
	int			ident;		/* our pid */
	int			iseq;		/* sequence number */
	gboolean		type;
	union {
		struct sockaddr     raw;
		struct sockaddr_in  v4;   	/* ipv4 ping addr */
		struct sockaddr_in6 v6;   	/* ipv6 ping addr */
	} addr;
	char			*host;
} ping_node;

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 *	This function taken from Mike Muuss' ping program.
 */
static int
in_cksum (u_short *addr, size_t len)
{
	size_t		nleft = len;
	u_short *	w = addr;
	int		sum = 0;
	u_short		answer = 0;

	/*
	 * The IP checksum algorithm is simple: using a 32 bit accumulator (sum)
	 * add sequential 16 bit words to it, and at the end, folding back all
	 * the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += *(u_char*)w;
	}

	/* Add back carry bits from top 16 bits to low 16 bits */

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return answer;
}

static ping_node *ping_new(const char *host, gboolean ipv6)
{
    ping_node *node;
    
    crm_malloc0(node, sizeof(ping_node));

    if(ipv6) {
	node->type = AF_INET6;
    } else {
	node->type = AF_INET;
    }
    
    node->host = crm_strdup(host);
    node->ident = getpid() & 0xFFFF;
    
    return node;
}

static gboolean ping_open(ping_node *node) 
{
    int ret_ga;
    char *hostname;
    struct addrinfo *res;
    struct addrinfo hints;

    /* getaddrinfo */
    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = node->type;
    hints.ai_socktype = SOCK_RAW;

    if(node->type == AF_INET6) {
	hints.ai_protocol = IPPROTO_ICMPV6;
    } else {
	hints.ai_protocol = IPPROTO_ICMP;
    }
	
    ret_ga = getaddrinfo(node->host, NULL, &hints, &res);
    if (ret_ga) {
	crm_err("getaddrinfo: %s", gai_strerror(ret_ga));
	return -1;
    }
	
    if (res->ai_canonname)
	hostname = res->ai_canonname;
    else
	hostname = node->host;

    crm_debug("Got address %s for %s", hostname, node->host);
    
    if (!res->ai_addr) {
	fprintf(stderr, "getaddrinfo failed");
	exit(1);
    }
	
    memcpy(&(node->addr.raw), res->ai_addr, res->ai_addrlen);
    node->fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    /* node->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol); */

    if(node->fd < 0) {
	cl_perror("Can't open socket to %s", hostname);
	return FALSE;
    }

    if(node->type == AF_INET6) {
	int sockopt;

	/* set recv buf for broadcast pings */
	sockopt = 48 * 1024;
	setsockopt(node->fd, SOL_SOCKET, SO_RCVBUF, (char *) &sockopt, sizeof(sockopt));
    }    

    return TRUE;
}

static gboolean ping_close(ping_node *node)
{
    int tmp_fd = node->fd;
    node->fd = -1;
	
    if (tmp_fd >= 0) {
	if(close(tmp_fd) < 0) {
	    cl_perror("Could not close ping socket");
	} else {
	    tmp_fd = -1;
	    crm_debug("Closed connection to %s", node->host);
	}
    }
	
    return (tmp_fd == -1);
}

#define MAXPACKETLEN	131072
#define ICMP6ECHOLEN	8	/* icmp echo header len excluding time */
#define ICMP6ECHOTMLEN  20
#define	DEFDATALEN	ICMP6ECHOTMLEN
#define	EXTRA		256	/* for AH and various other headers. weird. */
#define	IP6LEN		40

char *get_addr_text(struct sockaddr *addr, int addrlen);

char *
get_addr_text(struct sockaddr *addr, int addrlen)
{
    char *name = NULL;
    crm_malloc0(name, 1024);
    if (getnameinfo(addr, addrlen, name, 1024, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
	return (name);

    return crm_strdup("?");
}

static void
dump_v6_echo(ping_node *node, u_char *buf, int bytes, struct msghdr *mhdr)
{
	int fromlen;
	char *dest = node->host;
	struct icmp6_hdr *icp;
	struct sockaddr *from;

	if (!mhdr || !mhdr->msg_name ||
	    mhdr->msg_namelen != sizeof(struct sockaddr_in6) ||
	    ((struct sockaddr *)mhdr->msg_name)->sa_family != AF_INET6) {
	    crm_warn("invalid peername");
	    return;
	}

	fromlen = mhdr->msg_namelen;
	from = (struct sockaddr *)mhdr->msg_name;
	/* dest = get_addr_text(from, fromlen); */
	
	if (bytes < (int)sizeof(struct icmp6_hdr)) {
	    crm_warn("packet too short (%d bytes) from %s", bytes, dest);
	    crm_free(dest);
	    return;
	}
	icp = (struct icmp6_hdr *)buf;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY /* && myechoreply(icp) */) {
	    u_int16_t seq = ntohs(icp->icmp6_seq);
	    crm_debug("%d bytes from %s, icmp_seq=%u: %s", bytes, dest, seq, (char*)(buf + ICMP6ECHOLEN));

	} else {
	    crm_warn("Bad echo type: %d, code=%d, seq=%d, id=%d, check=%d", icp->icmp6_type,
		     icp->icmp6_code, ntohs(icp->icmp6_seq), icp->icmp6_id, icp->icmp6_cksum);
	}
	/* crm_free(dest); */
}

static void
dump_v4_echo(ping_node *node, u_char *buf, int bytes, struct msghdr *mhdr)
{
	int iplen, fromlen;
	const char *dest = node->host;

	struct ip *ip;
	struct icmp *icp;
	struct sockaddr *from;

	if (!mhdr || !mhdr->msg_name ||
	    mhdr->msg_namelen != sizeof(struct sockaddr_in) ||
	    ((struct sockaddr *)mhdr->msg_name)->sa_family != AF_INET) {
	    crm_warn("invalid peername\n");
	    return;
	}

	fromlen = mhdr->msg_namelen;
	from = (struct sockaddr *)mhdr->msg_name;
	/* dest = get_addr_text(from, fromlen); */
	/* inet_ntop(AF_INET, &(from->sin_addr), dest, sizeof(dest)); */

	ip = (struct ip*)buf;
	iplen = ip->ip_hl * 4;
	
	if (bytes < (iplen + sizeof(struct icmp))) {
	    crm_warn("packet too short (%d bytes) from %s\n", bytes, dest);
	    return;
	}

	/* Check the IP header */
	icp = (struct icmp*)(buf + iplen);

	if (icp->icmp_type == ICMP_ECHOREPLY /* && myechoreply(icp) */) {
	    crm_debug("%d bytes from %s, icmp_seq=%u: %s", bytes,
		      dest, ntohs(icp->icmp_seq), icp->icmp_data);
	} else {
	    crm_warn("Bad echo type: %d, code=%d, seq=%d, id=%d, check=%d", icp->icmp_type,
		     icp->icmp_code, ntohs(icp->icmp_seq), icp->icmp_id, icp->icmp_cksum);
	}
}

static void
ping_read(ping_node *node, int *lenp)
{
    int bytes;
    int fromlen;
    union {
	    struct sockaddr_in6 v6;
	    struct sockaddr_in  v4;
    } from;
    
    struct msghdr m;
    struct cmsghdr *cm;
    u_char buf[1024];
    struct iovec iov[2];

    int packlen;
    u_char *packet;
    packlen = DEFDATALEN + IP6LEN + ICMP6ECHOLEN + EXTRA;

    crm_malloc0(packet, packlen);
    if(node->type == AF_INET6) {
	fromlen = sizeof(from.v6);
    } else {
	fromlen = sizeof(from.v4);
    }
    
    m.msg_name = (caddr_t)&from;
    m.msg_namelen = sizeof(fromlen);
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (caddr_t)packet;
    iov[0].iov_len = packlen;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    cm = (struct cmsghdr *)buf;
    m.msg_control = (caddr_t)buf;
    m.msg_controllen = sizeof(buf);

    crm_debug_2("reading...");
    bytes = recvmsg(node->fd, &m, 0);
    crm_debug_2("Got %d bytes", bytes);
    
    if (bytes > 0) {
	if(node->type == AF_INET6) {
	    dump_v6_echo(node, packet, bytes, &m);
	} else {
	    dump_v4_echo(node, packet, bytes, &m);
	}
	
    } else if(bytes < 0) {
	cl_perror("recvmsg failed");

    } else {
	crm_err("Unexpected reply");
    }
}

static int
ping_write(ping_node *node, const char *data, size_t size)
{
	struct iovec iov[2];
	int i, bytes, namelen;
	static int ntransmitted = 5;
	struct msghdr smsghdr;
	u_char outpack[MAXPACKETLEN];

	 /* optional */
#if 0
	u_char *datap;
	datap = &outpack[ICMP6ECHOLEN + ICMP6ECHOTMLEN];
	for (i = ICMP6ECHOLEN; i < MAXPACKETLEN; ++i)
	    *datap++ = i;
#endif
	
	node->iseq = ntransmitted++;

	if(node->type == AF_INET6) {
	    struct icmp6_hdr *icp;
	    namelen = sizeof(struct sockaddr_in6);
	    bytes = ICMP6ECHOLEN + DEFDATALEN;

	    icp = (struct icmp6_hdr *)outpack;
	    memset(icp, 0, sizeof(*icp));
	    
	    icp->icmp6_code = 0;
	    icp->icmp6_cksum = 0;
	    icp->icmp6_type = ICMP6_ECHO_REQUEST;
	    icp->icmp6_id = htons(node->ident);
	    icp->icmp6_seq = ntohs(node->iseq);

	    memcpy(&outpack[ICMP6ECHOLEN], "beekhof-v6", 10);
	    
	} else {
	    struct icmp *icp;
	    namelen = sizeof(struct sockaddr_in);
	    bytes = sizeof(struct icmp) + 11;

	    icp = (struct icmp *)outpack;
	    memset(icp, 0, sizeof(*icp));

	    icp->icmp_code = 0;
	    icp->icmp_cksum = 0;
	    icp->icmp_type = ICMP_ECHO;
	    icp->icmp_id = htons(node->ident);
	    icp->icmp_seq = ntohs(node->iseq);

	    memcpy(icp->icmp_data, "beekhof-v4", 10);
	    icp->icmp_cksum = in_cksum((u_short *)icp, bytes);
	}

	
	memset(&smsghdr, 0, sizeof(smsghdr));
	smsghdr.msg_name = (caddr_t)&(node->addr);
	smsghdr.msg_namelen = namelen;
	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)outpack;
	iov[0].iov_len = bytes;
	smsghdr.msg_iov = iov;
	smsghdr.msg_iovlen = 1;

	i = sendmsg(node->fd, &smsghdr, 0);

	if (i < 0 || i != bytes)  {
	    if (i < 0) {
		cl_perror("sendmsg");
	    }
	    crm_err("Wrote only %d of %d chars", i, bytes);

	} else {
	    char dest[256];
	    if(node->type == AF_INET6) {
		inet_ntop(node->type, &node->addr.v6.sin6_addr, dest, 256);
	    } else {
		inet_ntop(node->type, &node->addr.v4.sin_addr, dest, 256);
	    }
	    crm_debug("Sent %d bytes to %s", i, dest);
	}
	
	return(0);
}

static void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s -n [-vdsS]\n", cmd);
 	fprintf(stream, "\t-n <string>\tthe attribute that changed\n");
 	fprintf(stream, "\t-v <string>\tthe attribute's value\n");
 	fprintf(stream, "\t\tIf no value is supplied, the attribute value for this node will be deleted\n");
 	fprintf(stream, "\t-d <string>\tthe time to wait (dampening) further changes occur\n");
 	fprintf(stream, "\t-s <string>\tthe attribute set in which to place the value\n");
	fprintf(stream, "\t\tMost people have no need to specify this\n");
 	fprintf(stream, "\t-S <string>\tthe section in which to place the value\n");
	fprintf(stream, "\t\tMost people have no need to specify this\n");
	fflush(stream);

	exit(exit_status);
}

#define OPTARGS "V?6h:"

int
main(int argc, char ** argv)
{
	ping_node *ping = NULL;
	int argerr = 0;
	int flag;
	int len = 0;
	gboolean ipv6 = FALSE;
	char *host = NULL;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose",  0, 0, 'V'},
		{"help",     0, 0, '?'},
		{"host",     1, 0, 'h'},
		{"use-ipv6", 0, 0, '6'},

		{0, 0, 0, 0}
	};
#endif
	
	crm_log_init("pingd2", LOG_DEBUG, TRUE, TRUE, argc, argv);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				alter_debug(DEBUG_INC);
				break;
			case 'h':
				host = crm_strdup(optarg);
				break;
			case '?':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case '6':
				ipv6 = TRUE;
				break;
			default:
			    crm_debug("%c", flag);
				++argerr;
				break;
		}
	}
    
	crm_debug_3("Option processing complete");
	
	if (optind > argc) {
		++argerr;
	}

	if (argc < 2) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	ping = ping_new(host, ipv6);
	ping_open(ping);
	while(1) {
	    ping_write(ping, "test", 4);
	    ping_read(ping, &len);
	    sleep(1);
	}
	ping_close(ping);
	
	return 0;
}
