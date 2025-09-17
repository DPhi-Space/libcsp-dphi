#ifndef CSP_IF_TCP_H
#define CSP_IF_TCP_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <csp/csp_interface.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configuration for the TCP interface
 */
typedef struct {
	char host[16];      // Peer IP address
	uint16_t lport;     // Local port
	uint16_t rport;     // Remote port
	int sockfd;         // Data socket
	int listen_sockfd;  // Listen socket (server mode)
	int is_server;      // 1 for server, 0 for client
	struct sockaddr_in peer_addr;
	pthread_t server_handle;
} csp_if_tcp_conf_t;
/**
 * Initialize and register a CSP TCP interface
 *
 * @param iface Pointer to the interface structure
 * @param ifconf Pointer to the TCP configuration
 */
int csp_if_tcp_init(csp_iface_t * iface, csp_if_tcp_conf_t * ifconf);

/**
 * TCP receive work function, used internally
 *
 * @param sockfd Socket file descriptor
 * @param unused Unused argument
 * @param iface Pointer to the interface
 * @return CSP error code
 */
int csp_if_tcp_rx_work(int sockfd, size_t unused, csp_iface_t * iface);

/**
 * Main loop for TCP receive thread (used internally)
 *
 * @param param Should be a pointer to the interface
 * @return Always NULL
 */
void * csp_if_tcp_rx_loop(void * param);

#ifdef __cplusplus
}
#endif

#endif  // CSP_IF_TCP_H
