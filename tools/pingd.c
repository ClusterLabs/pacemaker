
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

#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/lsb_exitcodes.h>

#include <crm/common/ipc.h>
#include <attrd.h>


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

#ifdef ON_LINUX
#include <asm/types.h>
#include <linux/errqueue.h>
# ifndef ICMP_FILTER
#  define ICMP_FILTER	1
struct icmp_filter {
	uint32_t	data;
};
# endif
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/lsb_exitcodes.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#if SUPPORT_HEARTBEAT
#  include <hb_api.h>
ll_cluster_t *pingd_cluster = NULL;
void do_node_walk(ll_cluster_t *hb_cluster);
#endif

/* GMainLoop *mainloop = NULL; */
#define OPTARGS	"V?p:a:d:s:S:h:Dm:N:Ui:"

GListPtr ping_list = NULL;
IPC_Channel *attrd = NULL;
GMainLoop*  mainloop = NULL;
GHashTable *ping_nodes = NULL;
const char *pingd_attr = "pingd";
gboolean do_filter = FALSE;
gboolean need_shutdown = FALSE;
gboolean stand_alone = FALSE;
gboolean do_updates = TRUE;

const char *attr_set = NULL;
const char *attr_section = NULL;
const char *attr_dampen = NULL;
int attr_multiplier = 1;
int pings_per_host = 5;
int ping_timeout = 5;
int re_ping_interval = 10;

int ident;		/* our pid */

typedef struct ping_node_s {
        int    			fd;		/* ping socket */
	int			iseq;		/* sequence number */
	gboolean		type;
	gboolean		extra_filters;
	union {
		struct sockaddr     raw;
		struct sockaddr_in  v4;   	/* ipv4 ping addr */
		struct sockaddr_in6 v6;   	/* ipv6 ping addr */
	} addr;
	char			dest[256];
	char			*host;
} ping_node;

void pingd_nstatus_callback(
	const char *node, const char *status, void *private_data);
void pingd_lstatus_callback(
	const char *node, const char *link, const char *status,
	void *private_data);
void send_update(int active);
int process_icmp_result(ping_node *node, struct sockaddr_in *whereto);

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

static const char *ping_desc(uint8_t type, uint8_t code)
{
    switch(type) {
	case ICMP_ECHOREPLY:
	    return "Echo Reply";
	case ICMP_ECHO:
	    return "Echo Request";
	case ICMP_PARAMPROB:
	    return "Bad Parameter";
	case ICMP_SOURCEQUENCH:
	    return "Packet lost, slow down";
	case ICMP_TSTAMP:
	    return "Timestamp Request";
	case ICMP_TSTAMPREPLY:
	    return "Timestamp Reply";
	case ICMP_IREQ:
	    return "Information Request";
	case ICMP_IREQREPLY:
	    return "Information Reply";
	    
	case ICMP_UNREACH:
	    switch(code) {
		case ICMP_UNREACH_NET:
		    return "Unreachable Network";
		case ICMP_UNREACH_HOST:
		    return "Unreachable Host";
		case ICMP_UNREACH_PROTOCOL:
		    return "Unreachable Protocol";
		case ICMP_UNREACH_PORT:
		    return "Unreachable Port";
		case ICMP_UNREACH_NEEDFRAG:
		    return "Unreachable: Fragmentation needed";
		case ICMP_UNREACH_SRCFAIL:
		    return "Unreachable Source Route";
		case ICMP_UNREACH_NET_UNKNOWN:
		    return "Unknown Network";
		case ICMP_UNREACH_HOST_UNKNOWN:
		    return "Unknown Host";
		case ICMP_UNREACH_ISOLATED:
		    return "Unreachable: Isolated";
		case ICMP_UNREACH_NET_PROHIB:
		    return "Prohibited network";
		case ICMP_UNREACH_HOST_PROHIB:
		    return "Prohibited host";
		case ICMP_UNREACH_FILTER_PROHIB:
		    return "Unreachable: Prohibited filter";
		case ICMP_UNREACH_TOSNET:
		    return "Unreachable: Type of Service and Network";
		case ICMP_UNREACH_TOSHOST:
		    return "Unreachable: Type of Service and Host";
		case ICMP_UNREACH_HOST_PRECEDENCE:
		    return "Unreachable: Prec vio";
		case ICMP_UNREACH_PRECEDENCE_CUTOFF:
		    return "Unreachable: Prec cutoff";
		default:
		    crm_err("Unreachable: Unknown subtype: %d", code);
		    return "Unreachable: Unknown Subtype";
	    }
	    break;

	case ICMP_REDIRECT:
	    switch(code) {
		case ICMP_REDIRECT_NET:
		    return "Redirect: Network";
		case ICMP_REDIRECT_HOST:
		    return "Redirect: Host";
		case ICMP_REDIRECT_TOSNET:
		    return "Redirect: Type of Service and Network";
		case ICMP_REDIRECT_TOSHOST:
		    return "Redirect: Type of Service and Host";
		default:
		    crm_err("Redirect: Unknown subtype: %d", code);
		    return "Redirect: Unknown Subtype";
	    }

	case ICMP_TIMXCEED:
	    switch(code) {
		case ICMP_TIMXCEED_INTRANS:
		    return "Timeout: TTL";
		case ICMP_TIMXCEED_REASS:
		    return "Timeout: Fragmentation reassembly";
		default:
		    crm_err("Timeout: Unkown subtype: %d", code);
		    return "Timeout: Unkown Subtype";
		}
	    break;

	default:
	    crm_err("Unknown type: %d", type);
	    return "Unknown type";
    }
}

#ifdef ON_LINUX
#  define MAX_HOST 1024
int process_icmp_result(ping_node *node, struct sockaddr_in *whereto)
{
    int rc = 0;
    char buf[512];
    struct iovec  iov;
    struct msghdr msg;
    struct icmphdr icmph;
    struct sockaddr_in target;
    struct cmsghdr *cmsg = NULL;
    struct sock_extended_err *s_err = NULL;

    iov.iov_base = &icmph;
    iov.iov_len = sizeof(icmph);
    msg.msg_name = (void*)&target;
    msg.msg_namelen = sizeof(target);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    
    rc = recvmsg(node->fd, &msg, MSG_ERRQUEUE|MSG_DONTWAIT);
    if (rc < 0 || rc < sizeof(icmph)) {
	crm_debug("No error message");
	return -1;
    }
	
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
	    s_err = (struct sock_extended_err *)CMSG_DATA(cmsg);
	}
    }

    CRM_ASSERT(s_err != NULL);
    
    if (s_err->ee_origin == SO_EE_ORIGIN_LOCAL) {
	if (s_err->ee_errno == EMSGSIZE) {
	    crm_info("local error: Message too long, mtu=%u", s_err->ee_info);
	} else {
	    crm_info("local error: %s", strerror(s_err->ee_errno));
	}
	return 0;
	
    } else if (s_err->ee_origin == SO_EE_ORIGIN_ICMP) {
	char ping_host[MAX_HOST];
	struct sockaddr_in *sin = (struct sockaddr_in*)(s_err+1);
	
	const char *ping_result = ping_desc(s_err->ee_type, s_err->ee_code);
	
	if (ntohs(icmph.un.echo.id) != ident) {
	    /* Result was not for us */
	    crm_info("Not our error (ident): %d %d", ntohs(icmph.un.echo.id), ident);
	    return -1;
	} else if (icmph.type != ICMP_ECHO) {
	    /* Not an error */
	    crm_info("Not an error");
	    return -1;

	} else {
	    char *target_s = inet_ntoa(*(struct in_addr *)&(target.sin_addr.s_addr));
	    char *whereto_s = inet_ntoa(*(struct in_addr *)&(whereto->sin_addr.s_addr));
	    if (safe_str_neq(target_s, whereto_s)) {
		/* Result was not for us */
		crm_info("Not our error (addr): %s %s", target_s, whereto_s);
		return -1;
	    }
	}
	
	/* snprintf(ping_host, MAX_HOST, "%s", inet_ntoa(*(struct in_addr *)&(sin->sin_addr.s_addr))); */
	snprintf(ping_host, MAX_HOST, "%s", inet_ntoa(sin->sin_addr));
	
	if (node->extra_filters == FALSE) {
	    /* Now that we got some sort of reply, add extra filters to
	     * ensure we keep getting the _right_ replies for dead hosts
	     */
	    struct icmp_filter filt;
	    crm_debug("Installing additional ICMP filters");
	    node->extra_filters = TRUE; /* only try once */
	    
	    filt.data = ~((1<<ICMP_SOURCE_QUENCH) | (1<<ICMP_REDIRECT) | (1<<ICMP_ECHOREPLY));
	    if (setsockopt(node->fd, SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt)) == -1) {
		crm_perror(LOG_WARNING, "setsockopt failed: Cannot install ICMP filters for %s", ping_host);
	    }
	}
	
	crm_info("From %s icmp_seq=%u %s", ping_host, ntohs(icmph.un.echo.sequence), ping_result);

    } else {
	crm_debug("else: %d", s_err->ee_origin);
    }
    
    return 0;
}
#else
int process_icmp_result(ping_node *node, struct sockaddr_in *whereto) 
{
    /* dummy function */
    return 0;
}
#endif

static ping_node *ping_new(const char *host)
{
    ping_node *node;
    
    crm_malloc0(node, sizeof(ping_node));

    if(strstr(host, ":")) {
	node->type = AF_INET6;
    } else {
	node->type = AF_INET;
    }
    
    node->host = crm_strdup(host);
    
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
	crm_warn("getaddrinfo: %s", gai_strerror(ret_ga));
	return FALSE;
    }
	
    if (res->ai_canonname)
	hostname = res->ai_canonname;
    else
	hostname = node->host;

    crm_debug("Got address %s for %s", hostname, node->host);
    
    if(!res->ai_addr) {
	crm_warn("getaddrinfo failed: no address");
	return FALSE;
    }
	
    memcpy(&(node->addr.raw), res->ai_addr, res->ai_addrlen);
    node->fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    /* node->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol); */

    if(node->fd < 0) {
	crm_perror(LOG_WARNING, "Can't open socket to %s", hostname);
	return FALSE;
    }

    if(node->type == AF_INET6) {
	int sockopt;

	inet_ntop(node->type, &node->addr.v6.sin6_addr, node->dest, sizeof(node->dest));
	
	/* set recv buf for broadcast pings */
	sockopt = 48 * 1024;
	setsockopt(node->fd, SOL_SOCKET, SO_RCVBUF, (char *) &sockopt, sizeof(sockopt));

    } else {
	inet_ntop(node->type, &node->addr.v4.sin_addr, node->dest, sizeof(node->dest));
    }

    if(ping_timeout > 0) {
	struct timeval timeout_opt;

	timeout_opt.tv_sec = ping_timeout;
	timeout_opt.tv_usec = 0;
	
	setsockopt(node->fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout_opt, sizeof(timeout_opt));
    }

#ifdef ON_LINUX
    {
	int dummy = 1;
	struct icmp_filter filt;
	filt.data = ~((1<<ICMP_SOURCE_QUENCH)|
		      (1<<ICMP_DEST_UNREACH)|
		      (1<<ICMP_TIME_EXCEEDED)|
		      (1<<ICMP_PARAMETERPROB)|
		      (1<<ICMP_REDIRECT)|
		      (1<<ICMP_ECHOREPLY));

	if (setsockopt(node->fd, SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt)) == -1) {
	    crm_perror(LOG_WARNING, "setsockopt failed: Cannot install ICMP filters for %s", node->dest);
	}

	setsockopt(node->fd, SOL_IP, IP_RECVERR, (char *)&dummy, sizeof(dummy));
    }
#endif    
    
    crm_debug("Opened connection to %s", node->dest);

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
	    crm_debug("Closed connection to %s", node->dest);
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

static int
dump_v6_echo(ping_node *node, u_char *buf, int bytes, struct msghdr *hdr)
{
	int fromlen;
	char dest[1024];
	
	struct icmp6_hdr *icp;
	struct sockaddr *from;

	if (!hdr || !hdr->msg_name || hdr->msg_namelen != sizeof(struct sockaddr_in6)
	    || ((struct sockaddr *)hdr->msg_name)->sa_family != AF_INET6) {
	    crm_warn("Invalid echo peer");
	    return -1;
	}

	fromlen = hdr->msg_namelen;
	from = (struct sockaddr *)hdr->msg_name;
	getnameinfo(from, fromlen, dest, sizeof(dest), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
	
	if (bytes < (int)sizeof(struct icmp6_hdr)) {
	    crm_warn("Invalid echo packet (too short: %d bytes) from %s", bytes, dest);
	    return -1;
	}
	icp = (struct icmp6_hdr *)buf;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY && ntohs(icp->icmp6_id) == ident) {
	    u_int16_t seq = ntohs(icp->icmp6_seq);
	    crm_debug("%d bytes from %s, icmp_seq=%u: %s",
		      bytes, dest, seq, (char*)(buf + ICMP6ECHOLEN));
	    return 1;
	}
	
	crm_warn("Bad echo (%d): type=%d, code=%d, seq=%d, id=%d, check=%d",
		 ICMP6_ECHO_REPLY, icp->icmp6_type,
		 icp->icmp6_code, ntohs(icp->icmp6_seq), icp->icmp6_id, icp->icmp6_cksum);
	return 0;
}

static int
dump_v4_echo(ping_node *node, u_char *buf, int bytes, struct msghdr *hdr)
{
	int iplen, fromlen;
	char from_host[1024];

	struct ip *ip;
	struct icmp *icp;
	struct sockaddr *from;

	if (hdr == NULL
	    || !hdr->msg_name
	    || hdr->msg_namelen != sizeof(struct sockaddr_in)
	    || ((struct sockaddr *)hdr->msg_name)->sa_family != AF_INET) {
	    crm_warn("Invalid echo peer");
	    return -1;
	}

	fromlen = hdr->msg_namelen;
	from = (struct sockaddr *)hdr->msg_name;
	getnameinfo(from, fromlen, from_host, sizeof(from_host), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);

	ip = (struct ip*)buf;
	iplen = ip->ip_hl * 4;
	
	if (bytes < (iplen + sizeof(struct icmp))) {
	    crm_warn("Invalid echo packet (too short: %d bytes) from %s", bytes, from_host);
	    return -1;
	}

	/* Check the IP header */
	icp = (struct icmp*)(buf + iplen);

	if(icp->icmp_type == ICMP_ECHO) {
	    /* Filter out the echo request when pinging the local host */ 
	    return -1;
	}
	
	crm_debug("Echo from %s (exp=%d, seq=%d, id=%d, dest=%s, data=%s): %s",
		  from_host, node->iseq, ntohs(icp->icmp_seq),
		  ntohs(icp->icmp_id), node->dest, icp->icmp_data,
		  ping_desc(icp->icmp_type, icp->icmp_code));

	if (icp->icmp_type == ICMP_ECHOREPLY
	    && node->iseq == ntohs(icp->icmp_seq)) {
	    crm_debug("%d bytes from %s, icmp_seq=%u: %s",
		      bytes, from_host, ntohs(icp->icmp_seq), icp->icmp_data);
	    return 1;
	}

	return process_icmp_result(node, (struct sockaddr_in*)from);
}

static int
ping_read(ping_node *node, int *lenp)
{
    int bytes;
    char fromaddr[128];
    struct msghdr m;
    struct cmsghdr *cm;
    u_char buf[1024];
    struct iovec iov[2];

    int packlen;
    u_char *packet;
    packlen = DEFDATALEN + IP6LEN + ICMP6ECHOLEN + EXTRA;

    crm_malloc0(packet, packlen);

  retry:
    m.msg_name = &fromaddr;
    m.msg_namelen = sizeof(fromaddr);
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (caddr_t)packet;
    iov[0].iov_len = packlen;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    cm = (struct cmsghdr *)buf;
    m.msg_control = (caddr_t)buf;
    m.msg_controllen = sizeof(buf);


    bytes = recvmsg(node->fd, &m, 0);
    crm_debug_2("Got %d bytes", bytes);
    
    if (bytes > 0) {
	int rc = 0;
	if(node->type == AF_INET6) {
	    rc = dump_v6_echo(node, packet, bytes, &m);
	} else {
	    rc = dump_v4_echo(node, packet, bytes, &m);
	}

	if(rc < 0) {
	    crm_info("Retrying...");
	    goto retry;
	    
	} else if(rc > 0) {
	    return TRUE;
	    
	} else {
	    return FALSE;
	}	
	
    } else if(bytes < 0) {
	process_icmp_result(node, (struct sockaddr_in*)&fromaddr);

    } else {
	crm_err("Unexpected reply");
    }
    return FALSE;
}

static int
ping_write(ping_node *node, const char *data, size_t size)
{
	struct iovec iov[2];
	int rc, bytes, namelen;
	/* static int ntransmitted = 9; */
	struct msghdr smsghdr;
	u_char outpack[MAXPACKETLEN];

	node->iseq++;

	if(node->type == AF_INET6) {
	    struct icmp6_hdr *icp;
	    namelen = sizeof(struct sockaddr_in6);
	    bytes = ICMP6ECHOLEN + DEFDATALEN;

	    icp = (struct icmp6_hdr *)outpack;
	    memset(icp, 0, sizeof(*icp));
	    
	    icp->icmp6_code = 0;
	    icp->icmp6_cksum = 0;
	    icp->icmp6_type = ICMP6_ECHO_REQUEST;
	    icp->icmp6_id = htons(ident);
	    icp->icmp6_seq = ntohs(node->iseq);

	    memcpy(&outpack[ICMP6ECHOLEN], "pingd-v6", 8);
	    
	} else {
	    struct icmp *icp;
	    namelen = sizeof(struct sockaddr_in);
	    bytes = sizeof(struct icmp) + 11;

	    icp = (struct icmp *)outpack;
	    memset(icp, 0, sizeof(*icp));

	    icp->icmp_code = 0;
	    icp->icmp_cksum = 0;
	    icp->icmp_type = ICMP_ECHO;
	    icp->icmp_id = htons(ident);
	    icp->icmp_seq = ntohs(node->iseq);

	    memcpy(icp->icmp_data, "pingd-v4", 8);
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

	rc = sendmsg(node->fd, &smsghdr, 0);

	if (rc < 0 || rc != bytes) {
	    crm_perror(LOG_WARNING, "Wrote %d of %d chars", rc, bytes);

	} else {
	    crm_debug("Sent %d bytes to %s", rc, node->dest);
	}
	
	return(0);
}

static gboolean
pingd_shutdown(int nsig, gpointer unused)
{
	need_shutdown = TRUE;
	send_update(-1);
	crm_info("Exiting");
	
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(0);
	}
	return FALSE;
}

static void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
	fprintf(stream, "\t--%s (-%c) \t\t\tThis text\n", "help", '?');
	fprintf(stream, "\t--%s (-%c) \t\tRun in daemon mode\n", "daemonize", 'D');
	fprintf(stream, "\t--%s (-%c) <filename>\tFile in which to store the process' PID\n"
		"\t\t\t\t\t* Default=/tmp/pingd.pid\n", "pid-file", 'p');
	fprintf(stream, "\t--%s (-%c) <string>\tName of the node attribute to set\n"
		"\t\t\t\t\t* Default=pingd\n", "attr-name", 'a');
	fprintf(stream, "\t--%s (-%c) <string>\tName of the set in which to set the attribute\n"
		"\t\t\t\t\t* Default=cib-bootstrap-options\n", "attr-set", 's');
	fprintf(stream, "\t--%s (-%c) <string>\tWhich part of the CIB to put the attribute in\n"
		"\t\t\t\t\t* Default=status\n", "attr-section", 'S');
	fprintf(stream, "\t--%s (-%c) <single_host_name>\tMonitor a subset of the ping nodes listed in ha.cf (can be specified multiple times)\n", "node", 'N');
	fprintf(stream, "\t--%s (-%c) <integer>\t\tHow long to wait for no further changes to occur before updating the CIB with a changed attribute\n", "attr-dampen", 'd');
	fprintf(stream, "\t--%s (-%c) <integer>\tFor every connected node, add <integer> to the value set in the CIB\n"
		"\t\t\t\t\t\t* Default=1\n", "value-multiplier", 'm');

	fflush(stream);

	exit(exit_status);
}

#if SUPPORT_HEARTBEAT
static gboolean
pingd_ha_dispatch(IPC_Channel *channel, gpointer user_data)
{
	gboolean stay_connected = TRUE;

	crm_debug_2("Invoked");

	while(pingd_cluster != NULL && IPC_ISRCONN(channel)) {
		if(pingd_cluster->llc_ops->msgready(pingd_cluster) == 0) {
			crm_debug_2("no message ready yet");
			break;
		}
		/* invoke the callbacks but dont block */
		pingd_cluster->llc_ops->rcvmsg(pingd_cluster, 0);
	}
	
	if (pingd_cluster == NULL || channel->ch_status != IPC_CONNECT) {
		if(need_shutdown == FALSE) {
			crm_crit("Lost connection to heartbeat service.");
		} else {
			crm_info("Lost connection to heartbeat service.");
		}
		stay_connected = FALSE;
	}
    
	return stay_connected;
}


static void
pingd_ha_connection_destroy(gpointer user_data)
{
	crm_debug_3("Invoked");
	if(need_shutdown) {
		/* we signed out, so this is expected */
		crm_info("Heartbeat disconnection complete");
		return;
	}

	crm_crit("Lost connection to heartbeat service!");
}

static gboolean
register_with_ha(void) 
{
	if(pingd_cluster == NULL) {
		pingd_cluster = ll_cluster_new("heartbeat");
	}
	if(pingd_cluster == NULL) {
		crm_err("Cannot create heartbeat object");
		return FALSE;
	}
	
	crm_debug("Signing in with Heartbeat");
	if (pingd_cluster->llc_ops->signon(
		    pingd_cluster, crm_system_name) != HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			pingd_cluster->llc_ops->errmsg(pingd_cluster));
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}

	do_node_walk(pingd_cluster);	

	crm_debug_3("Be informed of Node Status changes");
	if (HA_OK != pingd_cluster->llc_ops->set_nstatus_callback(
		    pingd_cluster, pingd_nstatus_callback, NULL)) {
		
		crm_err("Cannot set nstatus callback: %s",
			pingd_cluster->llc_ops->errmsg(pingd_cluster));
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}

	if (pingd_cluster->llc_ops->set_ifstatus_callback(
		    pingd_cluster, pingd_lstatus_callback, NULL) != HA_OK) {
		cl_log(LOG_ERR, "Cannot set if status callback");
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}
	
	crm_debug_3("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, pingd_cluster->llc_ops->ipcchan(
			pingd_cluster),
		FALSE, pingd_ha_dispatch, pingd_cluster,  
		pingd_ha_connection_destroy);

	return TRUE;
}

void
do_node_walk(ll_cluster_t *hb_cluster)
{
	const char *ha_node = NULL;

	/* Async get client status information in the cluster */
	crm_debug_2("Invoked");
	crm_debug_3("Requesting an initial dump of CRMD client_status");
	hb_cluster->llc_ops->client_status(
		hb_cluster, NULL, CRM_SYSTEM_CRMD, -1);
	
	crm_info("Requesting the list of configured nodes");
	hb_cluster->llc_ops->init_nodewalk(hb_cluster);

	do {
		const char *ha_node_type = NULL;
		const char *ha_node_status = NULL;

		ha_node = hb_cluster->llc_ops->nextnode(hb_cluster);
		if(ha_node == NULL) {
			continue;
		}
		
		ha_node_type = hb_cluster->llc_ops->node_type(
			hb_cluster, ha_node);
		if(safe_str_neq("ping", ha_node_type)) {
			crm_debug("Node %s: skipping '%s'",
				  ha_node, ha_node_type);
			continue;
		}

		if(do_filter
		   && g_hash_table_lookup(ping_nodes, ha_node) == NULL) {
			crm_debug("Filtering: %s", ha_node);
			continue;
		}
		
		ha_node_status = hb_cluster->llc_ops->node_status(
			hb_cluster, ha_node);

		crm_debug("Adding: %s=%s", ha_node, ha_node_status);
		g_hash_table_replace(ping_nodes, crm_strdup(ha_node),
				     crm_strdup(ha_node_status));

	} while(ha_node != NULL);

	hb_cluster->llc_ops->end_nodewalk(hb_cluster);
	crm_debug_2("Complete");
	send_update(-1);
}
#endif

static gboolean stand_alone_ping(gpointer data)
{
    int len = 0;
    int num_active = 0;
    
    crm_debug("Checking connectivity");
    slist_iter(
	ping, ping_node, ping_list, num, 
	
	if(ping_open(ping)) {

	    int lpc = 0;
	    for(;lpc < pings_per_host; lpc++) {
		ping_write(ping, "test", 4);
		if(ping_read(ping, &len)) {
		    crm_info("Node %s is alive", ping->host);
		    num_active++;
		    break;
		}
		sleep(1);
	    }
	}
	
	ping_close(ping);
	);

    send_update(num_active);
    
    CRM_ASSERT(Gmain_timeout_add(re_ping_interval*1000, stand_alone_ping, NULL) > 0);
    
    return FALSE;
}

int
main(int argc, char **argv)
{
	int lpc;
	int argerr = 0;
	int flag;
	char *pid_file = NULL;
	gboolean daemonize = FALSE;
	ping_node *p = NULL;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose",   0, 0, 'V'},
		{"help",      0, 0, '?'},
		{"pid-file",  1, 0, 'p'},		
		{"node",      1, 0, 'N'},		
		{"ping-host", 1, 0, 'h'}, /* legacy */
		{"attr-name", 1, 0, 'a'},		
		{"attr-set",  1, 0, 's'},		
		{"daemonize", 0, 0, 'D'},		
		{"attr-section", 1, 0, 'S'},		
		{"attr-dampen",  1, 0, 'd'},		
		{"value-multiplier",  1, 0, 'm'},		
		{"no-updates", 0, 0, 'U'},		
		{"interval",  1, 0, 'i'},		

		{0, 0, 0, 0}
	};
#endif
	pid_file = crm_strdup("/tmp/pingd.pid");

	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, pingd_shutdown, NULL, NULL);
	
	ping_nodes = g_hash_table_new_full(
                     g_str_hash, g_str_equal,
		     g_hash_destroy_str, g_hash_destroy_str);	

	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);
	
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
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'p':
				pid_file = crm_strdup(optarg);
				break;
			case 'a':
				pingd_attr = crm_strdup(optarg);
				break;
			case 'N':
			case 'h':
				stand_alone = TRUE;
				crm_debug("Adding ping host %s", optarg);
				p = ping_new(crm_strdup(optarg));
				ping_list = g_list_append(ping_list, p);
				break;
			case 'i':
				re_ping_interval = crm_get_msec(optarg) / 1000;
				break;
			case 's':
				attr_set = crm_strdup(optarg);
				break;
			case 'm':
				attr_multiplier = crm_parse_int(optarg, "1");
				break;
			case 'S':
				attr_section = crm_strdup(optarg);
				break;
			case 'd':
				attr_dampen = crm_strdup(optarg);
				break;
			case 'n':
				pings_per_host = crm_atoi(optarg, NULL);
				break;
			case 't':
				ping_timeout = crm_atoi(optarg, NULL);
				break;
			case 'D':
				daemonize = TRUE;
				break;
			case 'U':
				do_updates = FALSE;
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_GENERIC);
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				crm_err("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		crm_err("non-option ARGV-elements: ");
		printf("non-option ARGV-elements: ");
		while (optind < argc) {
			crm_err("%s ", argv[optind++]);
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	crm_make_daemon(crm_system_name, daemonize, pid_file);
	ident = getpid();

	if(do_updates == FALSE) {
	    goto start_ping;
	}
	
	for(lpc = 0; attrd == NULL && lpc < 30; lpc++) {
		crm_debug("attrd registration attempt: %d", lpc);
		sleep(5);
		attrd = init_client_ipc_comms_nodispatch(T_ATTRD);
	}
	
	if(attrd == NULL) {
		crm_err("attrd registration failed");
		cl_flush_logs();
		exit(LSB_EXIT_GENERIC);
	}

#if SUPPORT_AIS
	if(is_openais_cluster()) {
	    stand_alone = TRUE;
	}
#endif
	
#if SUPPORT_HEARTBEAT
	if(stand_alone == FALSE && register_with_ha() == FALSE) {
		crm_err("HA registration failed");
		cl_flush_logs();
		exit(LSB_EXIT_GENERIC);
	}
#endif
  start_ping:
	if(stand_alone && ping_list == NULL) {
	    crm_err("You must specify a list of hosts to monitor");
	    exit(LSB_EXIT_GENERIC);

	}
	
	crm_info("Starting %s", crm_system_name);
	mainloop = g_main_new(FALSE);

	if(stand_alone) {
	    stand_alone_ping(NULL);
	}

	g_main_run(mainloop);
	
	crm_info("Exiting %s", crm_system_name);	
	return 0;
}


static void count_ping_nodes(gpointer key, gpointer value, gpointer user_data)
{
	int *num_active = user_data;
	CRM_CHECK(num_active != NULL, return);

	if(need_shutdown) {
		return;
	}
	
	if(safe_str_eq(value, "ping")) {
		(*num_active)++;
	} else if(safe_str_eq(value, "up")) {
		(*num_active)++;
	}
}

void
send_update(int num_active) 
{
	xmlNode *update = create_xml_node(NULL, __FUNCTION__);
	crm_xml_add(update, F_TYPE, T_ATTRD);
	crm_xml_add(update, F_ORIG, crm_system_name);
	crm_xml_add(update, F_ATTRD_TASK, "update");
	crm_xml_add(update, F_ATTRD_ATTRIBUTE, pingd_attr);

	if(num_active < 0) {
	    g_hash_table_foreach(ping_nodes, count_ping_nodes, &num_active);
	}
	
	crm_info("%d active ping nodes", num_active);
	crm_xml_add_int(update, F_ATTRD_VALUE, attr_multiplier*num_active);
	
	if(attr_set != NULL) {
		crm_xml_add(update, F_ATTRD_SET,     attr_set);
	}
	if(attr_section != NULL) {
		crm_xml_add(update, F_ATTRD_SECTION, attr_section);
	}
	if(attr_dampen != NULL) {
		crm_xml_add(update, F_ATTRD_DAMPEN,  attr_dampen);
	}

	if(do_updates == FALSE) {
	    crm_log_xml_info(update, "pingd");
	    
	} else if(send_ipc_message(attrd, update) == FALSE) {
		crm_err("Could not send update");
		exit(1);
	}
	free_xml(update);
}

void
pingd_nstatus_callback(
	const char *node, const char * status,	void* private_data)
{
	crm_notice("Status update: Ping node %s now has status [%s]",
		   node, status);
	
	if(g_hash_table_lookup(ping_nodes, node) != NULL) {
		g_hash_table_replace(
			ping_nodes, crm_strdup(node), crm_strdup(status));
		send_update(-1);
	}
}

void
pingd_lstatus_callback(const char *node, const char *lnk, const char *status,
		       void *private)
{
	crm_notice("Status update: Ping node %s now has status [%s]",
		   node, status);
	pingd_nstatus_callback(node, status, private);
}

