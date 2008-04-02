
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

#ifdef linux
#	define	ICMP_HDR_SZ	sizeof(struct icmphdr)	/* 8 */
#else
#	define	ICMP_HDR_SZ	8
#endif

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
        struct sockaddr_in      addr;   	/* ping addr */
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

static gboolean ping_open(ping_node *node) 
{
    struct hostent *hent = NULL;

    hent = gethostbyname2(node->host, node->type);
    if (hent == NULL) {
	cl_perror("Unknown host %s", node->host);
	return FALSE;
    }
    
    node->fd = socket(node->type, SOCK_RAW, node->proto->p_proto);
    if(node->fd < 0) {
	cl_perror("Can't open socket");
	return FALSE;
    }

    if(node->type == AF_INET6) {
#if 0
	int sockopt;
	struct sockaddr_in6 addr = node->addr;

	addr.sin6_family = node->type;
	memcpy(&node->addr.sin6_addr, hent->h_addr, hent->h_length);

	sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
	setsockopt(node->fd, SOL_RAW, IPV6_CHECKSUM, (char *) &sockopt, sizeof(sockopt));
#endif
    } else {
    	node->addr.sin_family = node->type;
	memcpy(&node->addr.sin_addr, hent->h_addr, hent->h_length);
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

static char ping_pkt[MAXLINE];
static void *
ping_read(ping_node *node, int *lenp)
{
	union {
		char		cbuf[MAXLINE+ICMP_HDR_SZ];
		struct ip	ip;
	}buf;
	char *			msgstart;
	socklen_t		addr_len = sizeof(struct sockaddr);
   	struct sockaddr_in	their_addr; /* connector's addr information */
	struct ip *		ip;
	struct icmp		icp;
	int			numbytes;
	int			hlen;
	int			pktlen;
	
ReRead:	/* We recv lots of packets that aren't ours */
	
	if ((numbytes=recvfrom(node->fd, (void *) &buf.cbuf
	,	sizeof(buf.cbuf)-1, 0,	(struct sockaddr *)&their_addr
	,	&addr_len)) < 0) {
		if (errno != EINTR) {
		    cl_perror("Error receiving from socket");
		}
		return NULL;
	}
	/* Avoid potential buffer overruns */
	buf.cbuf[numbytes] = EOS;

	/* Check the IP header */
	ip = &buf.ip;
	hlen = ip->ip_hl * 4;

	if (numbytes < hlen + ICMP_MINLEN) {
	    crm_warn("ping packet too short (%d bytes) from %s",
		     numbytes, inet_ntoa(*(struct in_addr *) & their_addr.sin_addr.s_addr));
	    return NULL;
	}
	
	/* Now the ICMP part */	/* (there may be a better way...) */
	memcpy(&icp, (buf.cbuf + hlen), sizeof(icp));
	
	if (icp.icmp_type != ICMP_ECHOREPLY || icp.icmp_id != node->ident) {
		goto ReRead;	/* Not one of ours */
	}

	crm_debug("got %d byte packet from %s", numbytes, inet_ntoa(their_addr.sin_addr));
	msgstart = (buf.cbuf + hlen + ICMP_HDR_SZ);

	if (numbytes > 0) {
	    crm_debug("%s", msgstart);
	}
	
	pktlen = numbytes - hlen - ICMP_HDR_SZ;

	memcpy(ping_pkt, buf.cbuf + hlen + ICMP_HDR_SZ, pktlen);
	ping_pkt[pktlen] = 0;
	*lenp = pktlen + 1;
	return (ping_pkt);
}

/*
 * Send a heartbeat packet over ICMP ping channel
 *
 * The peculiar thing here is that we don't send the packet we're given at all
 *
 * Instead, we send out the packet we want to hear back from them, just
 * as though we were they ;-)  That's what comes of having such a dumb
 * device as a "member" of our cluster...
 *
 * We ignore packets we're given to write that aren't "status" packets.
 *
 */
/*
ping_write6() 
{
	struct sockaddr_in6 pingaddr;
	struct icmp6_hdr *pkt;
	int pingsock, c;
	int sockopt;
	char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];

	pingsock = create_icmp6_socket();

	memset(&pingaddr, 0, sizeof(struct sockaddr_in));

	pingaddr.sin6_family = AF_INET6;
	h = xgethostbyname2(host, AF_INET6);
	memcpy(&pingaddr.sin6_addr, h->h_addr, sizeof(pingaddr.sin6_addr));

	pkt = (struct icmp6_hdr *) packet;
	memset(pkt, 0, sizeof(packet));
	pkt->icmp6_type = ICMP6_ECHO_REQUEST;

	sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
	setsockopt(pingsock, SOL_RAW, IPV6_CHECKSUM, (char *) &sockopt,
			   sizeof(sockopt));

	c = sendto(pingsock, packet, sizeof(packet), 0,
			   (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in6));
}
*/
static int
ping_write(ping_node *node, const char *data, size_t size)
{
	int			rc;
	union{
		char*			buf;
		struct icmp		ipkt;
	}*icmp_pkt;
	struct icmp *		icp;
	size_t			pktsize;
	
	pktsize = size + ICMP_HDR_SZ;

	crm_malloc0(icmp_pkt, pktsize);

	icp = &(icmp_pkt->ipkt);
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(node->iseq);
	icp->icmp_id = node->ident;
	(node->iseq)++;

	memcpy(icp->icmp_data, data, size);

	/* Compute the ICMP checksum */
	icp->icmp_cksum = in_cksum((u_short *)icp, pktsize);

	if ((rc=sendto(node->fd, (void *) icmp_pkt, pktsize, MSG_DONTWAIT
	,	(struct sockaddr *)&node->addr
	,	sizeof(struct sockaddr))) != (ssize_t)pktsize) {
		cl_perror("Error sending packet: euid=%lu egid=%lu",
			  (unsigned long) geteuid(), (unsigned long) getegid());
		crm_free(icmp_pkt);
		return FALSE;
	}

	crm_debug("sent %d bytes to %s: %s", rc, inet_ntoa(node->addr.sin_addr), icp->icmp_data);
	crm_free(icmp_pkt);
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

#define OPTARGS "V?"

int
main(int argc, char ** argv)
{
	ping_node *ping = NULL;
	int argerr = 0;
	int flag;
	int len = 0;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},

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
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			default:
				++argerr;
				break;
		}
	}
    
	crm_debug_3("Option processing complete");

	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	ping = ping_new("127.0.0.1", FALSE);
	ping_open(ping);
	ping_write(ping, "test", 4);
	ping_read(ping, &len);
	ping_close(ping);
	    
	return 0;
}
