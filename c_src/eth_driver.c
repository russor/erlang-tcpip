/*****************************************************************************/
/*   Ethernet raw access driver                                              */
/*                                                                           */
/* erlang-tcpip, Copyright (C) 2004 Javier Paris                             */
/*                                                                           */
/* Licensed under the Apache License, Version 2.0 (the "License");           */
/* you may not use this file except in compliance with the License.          */
/* You may obtain a copy of the License at                                   */
/*                                                                           */
/* http://www.apache.org/licenses/LICENSE-2.0                                */
/*                                                                           */
/* Unless required by applicable law or agreed to in writing, software       */
/* distributed under the License is distributed on an "AS IS" BASIS,         */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  */
/* See the License for the specific language governing permissions and       */
/* limitations under the License.                                            */
/*                                                                           */
/*****************************************************************************/

#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <erl_driver.h>
#include <pcap.h>

#define BUFSIZE 65536
#define POLL_TIMEOUT 1000L

struct eth_data {
  ErlDrvPort port;
  int selectable_socket;
  pcap_t *pcap;
  char *iface;
};

static ErlDrvData eth_start(ErlDrvPort port, char *buff);
static void eth_stop(ErlDrvData drv_data);
static void eth_input(ErlDrvData drv_data, ErlDrvEvent event);
static void eth_timeout(ErlDrvData drv_data);
static ErlDrvSSizeT eth_control(ErlDrvData drv_data, unsigned int command,
                                char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen);
static void eth_outputv(ErlDrvData drv_data, ErlIOVec *ev);


static ErlDrvEntry eth_driver_entry = {
  NULL,                  /* init, N/A */
  eth_start,             /* start, called when port is opened */
  eth_stop,              /* stop, called when port is closed */
  NULL,                  /* output, called when erlang has sent */
  eth_input,             /* ready_input, called when input descriptor 
			    ready */
  NULL,                  /* ready_output, called when output 
			    descriptor ready */
  "eth_driver",          /* char *driver_name, the argument 
			    to open_port */
  NULL,                  /* finish, called when unloaded */
  NULL,                  /* void * that is not used (BC) */
  eth_control,           /* control, port_control callback */
  eth_timeout,           /* timeout, called on timeouts */
  eth_outputv,           /* outputv, vector output interface */
  NULL,					 /* Ready Async */
  NULL, 				 /* flush */
  NULL,					 /* call */
  NULL, 				 /* event */
  ERL_DRV_EXTENDED_MARKER,
  ERL_DRV_EXTENDED_MAJOR_VERSION,
  ERL_DRV_EXTENDED_MINOR_VERSION,
  0,
  NULL,
  NULL,
  NULL,
  NULL
};

static void attempt_to_read(ErlDrvData drv_data)
{
	struct eth_data *drv = (struct eth_data *) drv_data;
	ErlDrvBinary *buffer;
	const u_char *pkt;
	struct pcap_pkthdr h;

	if (drv_data == NULL) return;
	if (drv == NULL) return;

	memset(&h, 0, sizeof(h));

	buffer = driver_alloc_binary(BUFSIZE);
	pkt = pcap_next(drv->pcap, &h);
	while(buffer != NULL && pkt != NULL) {
		memcpy(buffer->orig_bytes, pkt, h.caplen);
                buffer->orig_size = h.caplen;
		driver_output_binary(drv->port, NULL, 0, buffer, 0, h.caplen);
		driver_free_binary(buffer);

		buffer = driver_alloc_binary(BUFSIZE);
		pkt = pcap_next(drv->pcap, &h);
	}

	// In the last iteration of the while an alloc is made, but
	//no driver_free is done, so it must be done here
	if (buffer) driver_free_binary(buffer);
	// Reset our timer..
	driver_set_timer(drv->port, POLL_TIMEOUT);
}


/*
 * Open up the PCAP interface
 */
static pcap_t *
open_pcap(const char *if_name)
{
	char	pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*pcap;

	pcap_errbuf[0]='\0';
	pcap = pcap_open_live(if_name,1500,1,0,pcap_errbuf);
	if (pcap_errbuf[0]!='\0') {
	    fprintf(stderr, "%s", pcap_errbuf);
	}
	if (!pcap) {
	    exit(1);
	}

	pcap_set_promisc(pcap, 1);
	return pcap;
}

/*
 * Get the socket from the PCAP library
 */
static int
get_pcap_socket(pcap_t *pcap)
{
	char	pcap_errbuf[PCAP_ERRBUF_SIZE];

	pcap_setnonblock(pcap, 1, pcap_errbuf);
	pcap_set_timeout(pcap, 10); // 10ms !
	return pcap_get_selectable_fd(pcap);
}

/*
 Loop reading packets from socket
*/
static void eth_input(ErlDrvData drv_data, ErlDrvEvent event)
{
	attempt_to_read(drv_data);
}

static void eth_timeout(ErlDrvData drv_data)
{
	attempt_to_read(drv_data);
}

static void eth_outputv(ErlDrvData drv_data, ErlIOVec *ev)
{
	int i;
	long pkt_size = 0, offset = 0;
	char *pkt;
	struct eth_data *drv = (struct eth_data *) drv_data;

	for(i = 0; i < ev->vsize; i++) {
		pkt_size += ev->iov[i].iov_len;
	}

	pkt = malloc(pkt_size);
	if (pkt != NULL) {
		for (i = 0; i < ev->vsize; i++) {
			memcpy(pkt + offset, ev->iov[i].iov_base, ev->iov[i].iov_len);
			offset += ev->iov[i].iov_len;
		}
		pcap_inject(drv->pcap, pkt, pkt_size);
	}
	free(pkt);
}


DRIVER_INIT(eth_driver)
{
  return &eth_driver_entry;
}

static ErlDrvData eth_start(ErlDrvPort port, char *buff)
{
  struct eth_data *drv = malloc(sizeof(struct eth_data));
  drv->port = port;
  drv->pcap = NULL;
  drv->iface = NULL;
  return (ErlDrvData) drv;
}

static void eth_stop(ErlDrvData drv_data)
{
  struct eth_data *drv = (struct eth_data *) drv_data;

  driver_select(drv->port, (ErlDrvEvent) drv->selectable_socket, DO_READ, 0);
  free(drv->iface);
  pcap_close(drv->pcap);
  free((ErlDrvPort *) drv_data);
}

static int get_iface_mtu(pcap_t *pcap, char *iface)
{
	int fd;
	struct ifreq ifr;

	if (!iface)
	    return 1500;

	fd = get_pcap_socket(pcap);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
	    perror("Error getting mtu:");
            return(1500);
	}

	return ifr.ifr_mtu;
}

static ErlDrvSSizeT eth_control(ErlDrvData drv_data, unsigned int command,
                                char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen)
{
	struct eth_data *drv = (struct eth_data *) drv_data;
	int selectable_sock;
	char *ifname;
	pcap_t *pcap;

	switch(command) {
	case 0: // specify the interface to bind
		ifname = malloc(len+1);

		strncpy(ifname, buf, len);
		ifname[len] = '\0';

		pcap = open_pcap(ifname);
		selectable_sock = get_pcap_socket(pcap);
		driver_select(drv->port, (ErlDrvEvent) selectable_sock, DO_READ, 1);
		drv->pcap = pcap;
		drv->selectable_socket = selectable_sock;
		drv->iface = ifname;

		driver_set_timer(drv->port, POLL_TIMEOUT);

		return 0;
		break;
	case 1: // get packets stats
		// st = get_packet_stats(drv->socket);
		if(rlen < 2*(sizeof(int))) {
			*rbuf=driver_realloc(*rbuf, sizeof(int));
		}
		/* TODO */
		((int *) (*rbuf))[0] = 0xDEAD;
		((int *) (*rbuf))[1] = 0xBEEF;

		return 2*sizeof(int);
		break;
	case 2: { // get iface MTU
		int mtu;
		mtu = get_iface_mtu(drv->pcap, drv->iface);

		if(rlen < (sizeof(int))) {
			*rbuf = driver_realloc(*rbuf, sizeof(int));
		}
		((int *) (*rbuf))[0] = mtu;

		return sizeof(int);
		break;
	}
	}
	return -1;
}
