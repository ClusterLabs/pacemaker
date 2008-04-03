
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
	struct protoent		*proto;
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
    const char *protocol = NULL;
    
    crm_malloc0(node, sizeof(ping_node));

    if(ipv6) {
	node->type = AF_INET6;
	protocol = "ipv6-icmp";
    } else {
	node->type = AF_INET;
	protocol = "icmp";
    }
    
    node->proto = getprotobyname(protocol);
    if(node->proto == NULL) {
	cl_perror("Unknown protocol %s", protocol);
	crm_free(node);
	return NULL;
    }
    
    node->host = crm_strdup(host);
    node->ident = getpid() & 0xFFFF;
    
    return node;
}

static struct addrinfo *get_ipv6_host(char *target, struct sockaddr_in6 *dst) 
{
	int ret_ga;
	char *hostname;
	struct addrinfo *res;
	struct addrinfo hints;

	/* getaddrinfo */
	bzero(&hints, sizeof(struct addrinfo));
	/* hints.ai_flags = AI_CANONNAME; */
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;

	ret_ga = getaddrinfo(target, NULL, &hints, &res);
	if (ret_ga) {
		fprintf(stderr, "ping6: %s\n", gai_strerror(ret_ga));
		exit(1);
	}
	if (res->ai_canonname)
		hostname = res->ai_canonname;
	else
		hostname = target;

	if (!res->ai_addr) {
	    fprintf(stderr, "getaddrinfo failed");
	    exit(1);
	}
	
	memcpy(dst, res->ai_addr, res->ai_addrlen);
	return res;
}

static gboolean ping_open(ping_node *node) 
{
    if(node->type == AF_INET6) {
	int sockopt;

	struct addrinfo *res = get_ipv6_host(node->host, &(node->addr.v6));
	
	printf("%d %d %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);
	node->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	/* set recv buf for broadcast pings */
	sockopt = 48 * 1024;
	setsockopt(node->fd, SOL_SOCKET, SO_RCVBUF, (char *) &sockopt, sizeof(sockopt));

    } else {
	struct hostent *hent = gethostbyname2(node->host, node->type);
	if (hent == NULL) {
	    cl_perror("Unknown host %s", node->host);
	    return FALSE;
	}

    	node->addr.v4.sin_family = node->type;
	memcpy(&node->addr.v4.sin_addr, hent->h_addr, hent->h_length);
	
	node->fd = socket(node->type, SOCK_RAW, node->proto->p_proto);	
    }    

    if(node->fd < 0) {
	cl_perror("Can't open socket");
	return FALSE;
    }
    
#if 0
    if (fcntl(node->fd, F_SETFD, FD_CLOEXEC)) {
	cl_perror("Error setting the close-on-exec flag");
    }
#endif

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

#define PING_MAX 1024
char ping_pkt[PING_MAX];
static int get_header_len(ping_node *node) 
{
    if(node->type == AF_INET6) {
	return sizeof(struct icmp6_hdr);
    }
    return sizeof(struct icmp);
}

#define MAXPACKETLEN	131072
#define ICMP6ECHOLEN	8	/* icmp echo header len excluding time */
#define ICMP6ECHOTMLEN  20
#define	DEFDATALEN	ICMP6ECHOTMLEN
#define	EXTRA		256	/* for AH and various other headers. weird. */
#define	IP6LEN		40

static const char *
get_addr_text(struct sockaddr *addr, int addrlen)
{
	static char buf[1024];
	int flag = 0;

	if (getnameinfo(addr, addrlen, buf, sizeof(buf), NULL, 0, flag) == 0)
		return (buf);
	else
		return "?";
}

static void
dump_echo(u_char *buf, int cc, struct msghdr *mhdr)
{
	struct icmp6_hdr *icp;
	struct sockaddr *from;
	int fromlen;
	u_int16_t seq;

	if (!mhdr || !mhdr->msg_name ||
	    mhdr->msg_namelen != sizeof(struct sockaddr_in6) ||
	    ((struct sockaddr *)mhdr->msg_name)->sa_family != AF_INET6) {
	    crm_warn("invalid peername\n");
	    return;
	}

	from = (struct sockaddr *)mhdr->msg_name;
	fromlen = mhdr->msg_namelen;
	if (cc < (int)sizeof(struct icmp6_hdr)) {
	    crm_warn("packet too short (%d bytes) from %s\n", cc, get_addr_text(from, fromlen));
	    return;
	}
	icp = (struct icmp6_hdr *)buf;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY /* && myechoreply(icp) */) {
	    seq = ntohs(icp->icmp6_seq);
	    
	    printf("Code=%d, seq=%d, id=%d, check=%d\n",
		   icp->icmp6_code, ntohs(icp->icmp6_seq), icp->icmp6_id, icp->icmp6_cksum);
	    
	    printf("%d bytes from %s, icmp_seq=%u: %s", cc,
		   get_addr_text(from, fromlen), seq, (char*)(buf + ICMP6ECHOLEN));
	}

	putchar('\n');
	fflush(stdout);
}

static void get_ping(int s) 
{
    int cc;
    int fromlen;
    struct sockaddr_in6 from;
    

    struct msghdr m;
    struct cmsghdr *cm;
    u_char buf[1024];
    struct iovec iov[2];

    int packlen;
    u_char *packet;
    packlen = DEFDATALEN + IP6LEN + ICMP6ECHOLEN + EXTRA;
    
    if (!(packet = (u_char *)malloc((u_int)packlen))) {
	crm_err("Unable to allocate packet");
	return;
    }
    
#if 0

    fd_set *fdmaskp;
    int fdmasks;
    fdmasks = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
    if ((fdmaskp = malloc(fdmasks)) == NULL)
	err(1, "malloc");
    
    
    memset(fdmaskp, 0, fdmasks);
    FD_SET(s, fdmaskp);
    cc = select(s + 1, fdmaskp, NULL, NULL, NULL);
    if (cc < 0) {
	if (errno != EINTR) {
	    warn("select");
	    sleep(1);
	}
	return;

    } else if (cc == 0)
	return;
#endif
    fromlen = sizeof(from);
    m.msg_name = (caddr_t)&from;
    m.msg_namelen = sizeof(from);
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (caddr_t)packet;
    iov[0].iov_len = packlen;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    cm = (struct cmsghdr *)buf;
    m.msg_control = (caddr_t)buf;
    m.msg_controllen = sizeof(buf);

    cc = recvmsg(s, &m, 0);
    if (cc < 0) {
	if (errno != EINTR) {
	    crm_warn("recvmsg");
	    sleep(1);
	}
	return;
    } else if (cc == 0) {
	/*
	 * receive control messages only. Process the
	 * exceptions (currently the only possiblity is
	 * a path MTU notification.)
	 */
	return;
    } else {
	/*
	 * an ICMPv6 message (probably an echoreply) arrived.
	 */
	dump_echo(packet, cc, &m);
    }
}

static void *
ping_read(ping_node *node, int *lenp)
{
    char		dest[PING_MAX];
	union {
		char		cbuf[PING_MAX];
		struct ip	ip;
		struct icmp	v4;
		
	} hdr;
	char *			msgstart;
	socklen_t		addr_len = sizeof(struct sockaddr);
   	struct sockaddr_in	their_addr; /* connector's addr information */
	struct ip *		ip;
	struct icmp		icp;
	int			numbytes;
	int			hlen;
	int			pktlen;
	int cmp_header_len = get_header_len(node);
	
	if(node->type == AF_INET6) {
	    /* inet_ntop(node->type, &node->addr.v6.sin6_addr, dest, 256); */
	    get_ping(node->fd);
	    return NULL;

	} else {
	    inet_ntop(node->type, &node->addr.v4.sin_addr, dest, 256);
	}
		
  ReRead:	/* We recv lots of packets that aren't ours */

	memset(&hdr, 0, PING_MAX);
	
	numbytes=recvfrom(node->fd, &hdr.cbuf, sizeof(hdr.cbuf)-1, 0, (struct sockaddr *)&their_addr, &addr_len);
	if (numbytes < 0) {
		if (errno != EINTR) {
		    cl_perror("Error receiving from socket");
		}
		return NULL;
	}
	
	
	crm_debug("got %d byte packet from %s", numbytes, dest);
	
	/* Avoid potential buffer overruns */
	hdr.cbuf[numbytes] = EOS;
	/* Check the IP header */
	ip = &hdr.ip;
	hlen = ip->ip_hl * 4;
	
	if (numbytes < hlen + cmp_header_len) {
	    crm_warn("ping packet too short (%d bytes) from %s, hlen=%d",
		     numbytes, inet_ntoa(*(struct in_addr *) & their_addr.sin_addr.s_addr), hlen);
	    return NULL;
	}
	
	/* Now the ICMP part */	/* (there may be a better way...) */
	memcpy(&icp, (hdr.cbuf + hlen), sizeof(icp));
	
	if (icp.icmp_type != ICMP_ECHOREPLY || icp.icmp_id != node->ident) {
	    goto ReRead;	/* Not one of ours */
	}
	
	crm_debug("got %d byte packet from %s", numbytes, get_addr_text((struct sockaddr *)&their_addr, addr_len));

	msgstart = (hdr.cbuf + hlen + cmp_header_len);

	if (numbytes > 0) {
	    crm_debug("%s", msgstart);
	}
	
	pktlen = numbytes - hlen - cmp_header_len;

	memcpy(ping_pkt, hdr.cbuf + hlen + cmp_header_len, pktlen);
	ping_pkt[pktlen] = 0;
	*lenp = pktlen + 1;
	return (ping_pkt);
}

static int
pinger(int s, struct sockaddr_in6 *dst, int ident)
{
	struct icmp6_hdr *icp;
	struct iovec iov[2];
	int i, cc;
	struct icmp6_nodeinfo *nip;
	static int ntransmitted = 5;
	int seq;
	struct msghdr smsghdr;
	u_char outpack[MAXPACKETLEN];

	 /* optional */
	u_char *datap;
	datap = &outpack[ICMP6ECHOLEN + ICMP6ECHOTMLEN];
	for (i = ICMP6ECHOLEN; i < MAXPACKETLEN; ++i)
	    *datap++ = i;
	
	icp = (struct icmp6_hdr *)outpack;
	nip = (struct icmp6_nodeinfo *)outpack;
	memset(icp, 0, sizeof(*icp));
	icp->icmp6_cksum = 0;
	seq = ntransmitted++;

	icp->icmp6_type = ICMP6_ECHO_REQUEST;
	icp->icmp6_code = 0;
	icp->icmp6_id = htons(ident);
	icp->icmp6_seq = ntohs(seq);
	memcpy(&outpack[ICMP6ECHOLEN], "beekhof", 7);
	cc = ICMP6ECHOLEN + DEFDATALEN;
	
	memset(&smsghdr, 0, sizeof(smsghdr));
	smsghdr.msg_name = (caddr_t)dst;
	smsghdr.msg_namelen = sizeof(struct sockaddr_in6);
	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)outpack;
	iov[0].iov_len = cc;
	smsghdr.msg_iov = iov;
	smsghdr.msg_iovlen = 1;

	i = sendmsg(s, &smsghdr, 0);

	if (i < 0 || i != cc)  {
	    if (i < 0) {
		crm_warn("sendmsg");
	    }
	    crm_err("ping6: wrote %d chars, ret=%d\n", cc, i);
	}

	return(0);
}

static int
ping_write(ping_node *node, const char *data, size_t size)
{
	int			rc;
	union {
		char*			buf;
		struct icmp		v4;
		struct icmp6_hdr        v6;
	} *hdr;
	size_t			pktsize;
	char dest[256];
	
	pktsize = size + get_header_len(node);

	crm_malloc0(hdr, pktsize);

	if(node->type == AF_INET6) {
	    crm_debug("Sending ipv6 ping");
	    pinger(node->fd, &(node->addr.v6), node->ident);
	    goto out;

	} else {
	    crm_debug("Sending ipv4 ping");
	    hdr->v4.icmp_type = ICMP_ECHO;
	    hdr->v4.icmp_code = 0;
	    hdr->v4.icmp_id = node->ident;
	    hdr->v4.icmp_seq = htons(node->iseq);
	    memcpy(hdr->v4.icmp_data, data, size);

	    hdr->v4.icmp_cksum = in_cksum((u_short *)&hdr->v4, pktsize);
	    (node->iseq)++;

	}

	rc = sendto(node->fd, hdr, pktsize, MSG_DONTWAIT, &(node->addr.raw), sizeof(struct sockaddr));
	if (rc != (ssize_t) pktsize) {
		cl_perror("Error sending packet");
		crm_free(hdr);
		return FALSE;
	}

  out:
	if(node->type == AF_INET6) {
	    inet_ntop(node->type, &node->addr.v6.sin6_addr, dest, 256);
	} else {
	    inet_ntop(node->type, &node->addr.v4.sin_addr, dest, 256);
	}
	
	crm_debug("sent %d bytes to %s: %s", rc, dest, data);
	crm_free(hdr);
	return TRUE;
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
