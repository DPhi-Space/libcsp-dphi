#include <arpa/inet.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_id.h>
#include <csp/csp_interface.h>
#include <csp/interfaces/csp_if_tcp.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL (0)
#endif

static bool connected = false;

bool csp_if_tcp_connected() {
	return connected;
}
static int csp_if_tcp_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	csp_if_tcp_conf_t * ifconf = iface->driver_data;

	if (ifconf->sockfd <= 0) {
		csp_buffer_free(packet);
		return CSP_ERR_NONE;
	}

	csp_id_prepend(packet);

	// Send packet data directly (no length header)
	ssize_t sent = send(ifconf->sockfd, packet->frame_begin, packet->frame_length, MSG_NOSIGNAL);
	if (sent != packet->frame_length) {
		csp_buffer_free(packet);
		return CSP_ERR_DRIVER;
	}

	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

int csp_if_tcp_rx_work(int sockfd, size_t unused, csp_iface_t * iface) {
	csp_packet_t * packet = csp_buffer_get(0);
	if (packet == NULL) {
		return CSP_ERR_NOMEM;
	}

	/* Setup RX frame to point to ID */
	int header_size = csp_id_setup_rx(packet);

	// Receive data directly (no length header)
	ssize_t received = recv(sockfd, packet->frame_begin, sizeof(packet->data) + header_size, 0);

	if (received < header_size) {
		csp_buffer_free(packet);
		return CSP_ERR_DRIVER;
	}

	packet->frame_length = received;

	/* Parse the frame and strip the ID field */
	if (csp_id_strip(packet) != 0) {
		csp_buffer_free(packet);
		return CSP_ERR_INVAL;
	}

	csp_qfifo_write(packet, iface, NULL);
	return CSP_ERR_NONE;
}

static int csp_if_tcp_connect(csp_if_tcp_conf_t * ifconf) {
	struct sockaddr_in server_addr = {0};
	struct sockaddr_in local_addr = {0};

	ifconf->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (ifconf->sockfd < 0) {
		csp_print("TCP: Failed to create socket\n");
		return -1;
	}

	// Bind to local port if specified (optional for client)
	if (ifconf->lport != 0) {
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port = htons(ifconf->lport);

		if (bind(ifconf->sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
			csp_print("TCP: Failed to bind to local port %d - %s\n", ifconf->lport, strerror(errno));
			close(ifconf->sockfd);
			ifconf->sockfd = 0;
			return -1;
		}
	}

	server_addr.sin_family = AF_INET;
	if (inet_aton(ifconf->host, &server_addr.sin_addr) == 0) {
		csp_print("TCP: Invalid peer address %s\n", ifconf->host);
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
		return -1;
	}
	server_addr.sin_port = htons(ifconf->rport);

	if (connect(ifconf->sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		csp_print("TCP: Failed to connect to %s:%d - %s\n", ifconf->host, ifconf->rport, strerror(errno));
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
		return -1;
	}

	csp_print("TCP: Connected to %s:%d\n", ifconf->host, ifconf->rport);
	return 0;
}

static int csp_if_tcp_setup_server(csp_if_tcp_conf_t * ifconf) {
	struct sockaddr_in server_addr = {0};
	int opt = 1;

	ifconf->listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (ifconf->listen_sockfd < 0) {
		csp_print("TCP: Failed to create listen socket\n");
		return -1;
	}

	// Allow socket reuse
	if (setsockopt(ifconf->listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		csp_print("TCP: Failed to set SO_REUSEADDR\n");
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(ifconf->lport);

	if (bind(ifconf->listen_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		csp_print("TCP: Failed to bind to port %d - %s\n", ifconf->lport, strerror(errno));
		close(ifconf->listen_sockfd);
		ifconf->listen_sockfd = 0;
		return -1;
	}

	if (listen(ifconf->listen_sockfd, 1) < 0) {
		csp_print("TCP: Failed to listen on port %d\n", ifconf->lport);
		close(ifconf->listen_sockfd);
		ifconf->listen_sockfd = 0;
		return -1;
	}

	csp_print("TCP: Listening on port %d\n", ifconf->lport);
	return 0;
}

void * csp_if_tcp_rx_loop(void * param) {
	csp_iface_t * iface = param;
	csp_if_tcp_conf_t * ifconf = iface->driver_data;

	// Setup server socket if we're in server mode
	if (ifconf->is_server) {
		if (csp_if_tcp_setup_server(ifconf) != 0) {
			csp_print("TCP: Failed to setup server\n");
			return NULL;
		}

		csp_print("TCP: Waiting for client connection...\n");

		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		ifconf->sockfd = accept(ifconf->listen_sockfd, (struct sockaddr *)&client_addr, &client_len);

		if (ifconf->sockfd < 0) {
			csp_print("TCP: Failed to accept connection\n");
			connected = false;
			return NULL;
		}

		csp_print("TCP: Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		connected = true;
	} else {
		// Client mode - connect to server
		while (ifconf->sockfd <= 0) {
			if (csp_if_tcp_connect(ifconf) == 0) {
				connected = true;
				break;
			}
			csp_print("TCP: Retrying connection in 1 second...\n");
			connected = false;
			sleep(1);
		}
	}

	// Main receive loop
	while (1) {
		int ret = csp_if_tcp_rx_work(ifconf->sockfd, 0, iface);
		if (ret == CSP_ERR_INVAL) {
			iface->rx_error++;
		} else if (ret == CSP_ERR_NOMEM) {
			usleep(10000);
		} else if (ret == CSP_ERR_DRIVER) {
			// Connection lost, try to reconnect if client
			csp_print("TCP: Connection lost\n");
			close(ifconf->sockfd);
			ifconf->sockfd = 0;
			connected = false;

			if (!ifconf->is_server) {
				// Client mode - reconnect
				while (ifconf->sockfd <= 0) {
					if (csp_if_tcp_connect(ifconf) == 0) {
						break;
					}
					csp_print("TCP: Retrying connection in 1 second...\n");
					sleep(1);
				}
			} else {
				// Server mode - wait for new connection
				csp_print("TCP: Waiting for new client connection...\n");
				struct sockaddr_in client_addr;
				socklen_t client_len = sizeof(client_addr);
				ifconf->sockfd = accept(ifconf->listen_sockfd, (struct sockaddr *)&client_addr, &client_len);

				if (ifconf->sockfd >= 0) {
					csp_print("TCP: Client reconnected from %s:%d\n", inet_ntoa(client_addr.sin_addr),
							  ntohs(client_addr.sin_port));
				}
			}
		}
	}

	return NULL;
}

int csp_if_tcp_init(csp_iface_t * iface, csp_if_tcp_conf_t * ifconf) {
	pthread_attr_t attributes;
	int ret;

	iface->driver_data = ifconf;

	// Initialize socket descriptors
	ifconf->sockfd = 0;
	ifconf->listen_sockfd = 0;

	if (!ifconf->is_server) {
		if (inet_aton(ifconf->host, &ifconf->peer_addr.sin_addr) == 0) {
			csp_print("TCP: Unknown peer address %s\n", ifconf->host);
		}
		csp_print("TCP: Will connect to %s:%d\n", ifconf->host, ifconf->rport);
		if (ifconf->lport != 0) {
			csp_print("TCP: Will bind to local port %d\n", ifconf->lport);
		}
	} else {
		csp_print("TCP: Will listen on port %d (accepting connections from any port)\n", ifconf->lport);
	}

	/* Start server thread */
	ret = pthread_attr_init(&attributes);
	if (ret != 0) {
		csp_print("csp_if_tcp_init: pthread_attr_init failed: %s: %d\n", strerror(ret), ret);
		return CSP_ERR_INVAL;
	}

	ret = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		csp_print("csp_if_tcp_init: pthread_attr_setdetachstate failed: %s: %d\n", strerror(ret), ret);
		return CSP_ERR_INVAL;
	}

	ret = pthread_create(&ifconf->server_handle, &attributes, csp_if_tcp_rx_loop, iface);
	if (ret != 0) {
		csp_print("csp_if_tcp_init: pthread_create failed: %s: %d\n", strerror(ret), ret);
		return CSP_ERR_INVAL;
	}

	ret = pthread_attr_destroy(&attributes);
	if (ret != 0) {
		csp_print("csp_if_tcp_init: pthread_attr_destroy failed: %s: %d\n", strerror(ret), ret);
		return CSP_ERR_INVAL;
	}

	/* Register interface */
	iface->name = "TCP";
	iface->nexthop = csp_if_tcp_tx;
	csp_iflist_add(iface);

	return CSP_ERR_NONE;
}
