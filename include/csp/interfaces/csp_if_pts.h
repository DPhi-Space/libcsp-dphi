#ifndef CSP_IF_PTS_H
#define CSP_IF_PTS_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <csp/interfaces/csp_if_kiss.h>
#include <csp/csp_interface.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char host[16];
	uint16_t rport;
	int sockfd;
	struct sockaddr_in peer_addr;
	pthread_t server_handle;
} csp_if_pts_conf_t;

int csp_if_pts_init(csp_iface_t ** return_iface, csp_if_pts_conf_t * ifconf, const char * ifname, int addr);
int csp_if_pts_rx_work(int sockfd, size_t unused, csp_iface_t * iface);
void * csp_if_pts_rx_loop(void * param);
int csp_if_pts_send_termios_config(csp_if_pts_conf_t * ifconf, uint16_t port, uint32_t baudrate);

#ifdef __cplusplus
}
#endif

#endif
