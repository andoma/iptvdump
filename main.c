/*
 *  Transport stream logger
 *  Copyright (C) 2007 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/ioctl.h>
#include <errno.h>
#include <poll.h>


#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netdevice.h>

#include "ts.h"

int raw_dump;
int pcr_analysis;

/**
 * Bind a socket to the given group & port on the given interface 
 */
static int
openfd(const char *group, const char *iface, int port)
{
  struct ifreq ifr;
  int ifindex, fd;
  struct sockaddr_in sin;
  struct ip_mreqn m;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = 0;
    
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd == -1) {
    fprintf(stderr, "Cannot open socket");
    exit(1);
  }

  if(ioctl(fd, SIOCGIFINDEX, &ifr) != 0) {
    fprintf(stderr, "interface %s not found\n", iface);
    exit(1);
  }

  ifindex = ifr.ifr_ifindex;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = inet_addr(group);

  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
    fprintf(stderr, "cannot bind %s:%d -- %s", 
	    group, port, strerror(errno));
    exit(1);
  }

  memset(&m, 0, sizeof(m));
  m.imr_multiaddr.s_addr = inet_addr(group);
  m.imr_address.s_addr = 0;
  m.imr_ifindex = ifindex;

  if(setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP, &m, 
		sizeof(struct ip_mreqn)) == -1) {
    fprintf(stderr, "cannot join %s on %s -- %s", 
	    group, iface, strerror(errno));
    exit(1);
  }
  return fd;
}


/**
 * Receive and decode a UDP packet containing transport stream packets
 */
static void
tsinput(int fd)
{
  uint8_t buf[1500], *p;
  int x;

  x = read(fd, buf, 1500);
  if(x < 1) {
    perror("read from UDP socket");
    exit(1);
  }
  
  if(x % 188) {
    fprintf(stderr, "ERR: Got non-integral number of TS packets (%d bytes)\n",
	    x);
    return;
  }

  if(raw_dump) {
    if(write(1, buf, x) != x) {
      fprintf(stderr, "ERR: Write failed\n");
      exit(2);
    }
    return;
  }

  x /= 188;
  p = buf;
  while(x--) {
    process_ts_packet(p);
    p += 188;
  }
}


  
/**
 * Main loop
 */ 
int
main(int argc, char **argv)
{
  int c, fd, r;
  const char *group = NULL, *iface = NULL;
  int port = -1;
  struct pollfd fds;

  while((c = getopt(argc, argv, "g:i:p:dP")) != -1) {
    switch(c) {

    case 'g':
      group = optarg;
      break;

    case 'i':
      iface = optarg;
      break;
      
    case 'p':
      port = atoi(optarg);
      break;

    case 'P':
      pcr_analysis = 1;
      break;

    case 'd':
      raw_dump = 1;
      break;
    }
  }

  if(port == -1 || group == NULL || iface == NULL) {
    fprintf(stderr, "Missing arguments\n");
    exit(1);
  }

  fd = openfd(group, iface, port);

  fds.fd = fd;
  fds.events = POLLIN;
  
  while(1) {
    r = poll(&fds, 1, 1000);
    if(r < 0) {
      perror("poll");
      exit(1);
    } else if(r == 0) {
      fprintf(stderr, "ERR: No data received\n");
    } else {
      tsinput(fd);
    }
  }
  return 0;
}
