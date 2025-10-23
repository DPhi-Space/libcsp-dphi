#include <arpa/inet.h>
#include <csp/csp.h>
#include <csp/csp_crc32.h>
#include <stdlib.h>
#include <csp/interfaces/csp_if_kiss.h>
#include <csp/csp_debug.h>
#include <csp/csp_id.h>
#include <csp/csp_interface.h>
#include <csp/interfaces/csp_if_pts.h>
#include <csp/interfaces/csp_if_kiss.h>

#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL (0)
#endif

#define B9600    0x00000D
#define CS8      0x30
#define CREAD    0x0800
#define CLOCAL   0x0800
#define FEND     0xC0
#define FESC     0xDB
#define TFEND    0xDC
#define TFESC    0xDD
#define TNC_DATA 0x00

#pragma pack(push, 1)
typedef struct {
	uint32_t c_iflag;
	uint32_t c_oflag;
	uint32_t c_cflag;
	uint32_t c_lflag;
	uint8_t c_line;
	uint8_t c_cc[19];
	uint32_t c_ispeed;
	uint32_t c_ospeed;
} termios2_packet_t;
#pragma pack(pop)

typedef struct {
	char name[CSP_IFLIST_NAME_MAX + 1];
	csp_iface_t iface;
	csp_kiss_interface_data_t ifdata;
} pts_context_t;
/* ---------------- TX ---------------- */

static int csp_if_pts_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	csp_if_pts_conf_t * ifconf = iface->driver_data;
	csp_kiss_interface_data_t * ifdata = iface->interface_data;
	void * driver = iface->driver_data;

	if (ifconf->sockfd <= 0) {
		csp_buffer_free(packet);
		return CSP_ERR_DRIVER;
	}
	csp_crc32_append(packet);
	csp_id_prepend(packet);

	/* Transmit data */
	const unsigned char start[] = {FEND, TNC_DATA};
	const unsigned char esc_end[] = {FESC, TFEND};
	const unsigned char esc_esc[] = {FESC, TFESC};
	const unsigned char * data = packet->frame_begin;

	// ifdata->tx_func(driver, start, sizeof(start));
	ssize_t sent = send(ifconf->sockfd, start, sizeof(start), MSG_NOSIGNAL);
	if (sent != (ssize_t)sizeof(start)) {
		csp_print("PTS: failed to send data (%zd/%zu): %s\n",
				  sent, sizeof(start), strerror(errno));
		return CSP_ERR_DRIVER;
	}

	for (unsigned int i = 0; i < packet->frame_length; i++, ++data) {
		if (*data == FEND) {
			// ifdata->tx_func(driver, esc_end, sizeof(esc_end));
			sent = send(ifconf->sockfd, esc_end, sizeof(esc_end), MSG_NOSIGNAL);
			if (sent != (ssize_t)sizeof(esc_end)) {
				csp_print("PTS: failed to send data (%zd/%zu): %s\n",
						  sent, sizeof(esc_end), strerror(errno));
				return CSP_ERR_DRIVER;
			}
			continue;
		}
		if (*data == FESC) {
			// ifdata->tx_func(driver, esc_esc, sizeof(esc_esc));
			sent = send(ifconf->sockfd, esc_esc, sizeof(esc_esc), MSG_NOSIGNAL);
			if (sent != (ssize_t)sizeof(esc_esc)) {
				csp_print("PTS: failed to send data (%zd/%zu): %s\n",
						  sent, sizeof(esc_esc), strerror(errno));
				return CSP_ERR_DRIVER;
			}
			continue;
		}
		// ifdata->tx_func(driver, data, 1);
		sent = send(ifconf->sockfd, data, 1, MSG_NOSIGNAL);
		if (sent != 1) {
			csp_print("PTS: failed to send data (%zd/%zu): %s\n",
					  sent, 1, strerror(errno));
			return CSP_ERR_DRIVER;
		}
	}
	const unsigned char stop[] = {FEND};
	// ifdata->tx_func(driver, stop, sizeof(stop));

	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static int pts_driver_tx(void * driver_data, const unsigned char * data, size_t data_length) {
	return CSP_ERR_NONE;
}
/* ---------------- RX ---------------- */

int csp_if_pts_rx(int sockfd, size_t unused, csp_iface_t * iface) {
	csp_kiss_interface_data_t * ifdata = (csp_kiss_interface_data_t *)iface->interface_data;
	if (ifdata == NULL) {
		csp_print("PTS: interface_data (ifdata) is NULL\n");
		return CSP_ERR_INVAL;
	}

	uint8_t rxbuf[2048]; /* choose size according to expected stream */
	ssize_t received = recv(sockfd, rxbuf, sizeof(rxbuf), 0);

	if (received <= 0) {
		return CSP_ERR_DRIVER;
	}

	csp_kiss_rx(iface, rxbuf, (size_t)received, NULL);

	return CSP_ERR_NONE;
}
/* ---------------- CONNECT ---------------- */

static int csp_if_pts_connect(csp_if_pts_conf_t * ifconf) {
	struct sockaddr_in server_addr = {0};

	ifconf->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (ifconf->sockfd < 0) {
		csp_print("PTS: Failed to create socket\n");
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(ifconf->rport);

	if (inet_aton(ifconf->host, &server_addr.sin_addr) == 0) {
		csp_print("PTS: Invalid peer address %s\n", ifconf->host);
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
		return -1;
	}

	if (connect(ifconf->sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		csp_print("PTS: Failed to connect to %s:%d - %s\n",
				  ifconf->host, ifconf->rport, strerror(errno));
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
		return -1;
	}

	csp_print("PTS: Connected to %s:%d\n", ifconf->host, ifconf->rport);
	return 0;
}

/* ---------------- RX THREAD ---------------- */

void * csp_if_pts_rx_loop(void * param) {
	csp_iface_t * iface = param;
	csp_if_pts_conf_t * ifconf = iface->driver_data;

	// Keep trying until connection is established
	while (ifconf->sockfd <= 0) {
		if (csp_if_pts_connect(ifconf) == 0) {
			break;
		}
		csp_print("PTS: Retrying connection in 1 second...\n");
		sleep(1);
	}

	csp_if_pts_send_termios_config(ifconf, 1, 9600);

	while (1) {
		int ret = csp_if_pts_rx(ifconf->sockfd, 0, iface);
		if (ret == CSP_ERR_INVAL) {
			iface->rx_error++;
		} else if (ret == CSP_ERR_NOMEM) {
			usleep(10000);
		} else if (ret == CSP_ERR_DRIVER) {
			csp_print("PTS: Connection lost, reconnecting...\n");
			close(ifconf->sockfd);
			ifconf->sockfd = 0;

			while (ifconf->sockfd <= 0) {
				if (csp_if_pts_connect(ifconf) == 0) {
					csp_if_pts_send_termios_config(ifconf, 1, 9600);
					break;
				}
				csp_print("PTS: Retrying connection in 1 second...\n");
				sleep(1);
			}
		}
	}
	return NULL;
}

/* ---------------- INIT ---------------- */

int csp_if_pts_init(csp_iface_t ** return_iface, csp_if_pts_conf_t * ifconf, const char * ifname, int addr) {
	pthread_attr_t attr;
	int ret = 0;
	struct sockaddr_in server_addr = {0};
	struct timeval timeout;

	if (ifconf == NULL) {
		return CSP_ERR_INVAL;
	}

	ifconf->sockfd = 0;

	if (ifconf->host[sizeof(ifconf->host) - 1] != '\0') {
		ifconf->host[sizeof(ifconf->host) - 1] = '\0';
	}

	if (inet_aton(ifconf->host, &ifconf->peer_addr.sin_addr) == 0) {
		csp_print("PTS: Unknown peer address %s\n", ifconf->host);
	}

	csp_print("PTS: Will connect to %s:%d\n", ifconf->host, ifconf->rport);

	ifconf->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (ifconf->sockfd < 0) {
		csp_print("PTS: Failed to create socket\n");
		return CSP_ERR_DRIVER;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(ifconf->rport);

	if (inet_aton(ifconf->host, &server_addr.sin_addr) == 0) {
		csp_print("PTS: Invalid address %s\n", ifconf->host);
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
		return CSP_ERR_DRIVER;
	}

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(ifconf->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(ifconf->sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	if (connect(ifconf->sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		csp_print("PTS: Connection failed to %s:%d - %s\n", ifconf->host, ifconf->rport, strerror(errno));
		close(ifconf->sockfd);
		ifconf->sockfd = 0;
	} else {
		csp_print("PTS: Connected to %s:%d\n", ifconf->host, ifconf->rport);
	}

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		csp_print("PTS: pthread_attr_init failed: %s\n", strerror(ret));
		if (ifconf->sockfd > 0) {
			close(ifconf->sockfd);
			ifconf->sockfd = 0;
		}
		return CSP_ERR_INVAL;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		csp_print("PTS: pthread_attr_setdetachstate failed: %s\n", strerror(ret));
		pthread_attr_destroy(&attr);
		if (ifconf->sockfd > 0) {
			close(ifconf->sockfd);
			ifconf->sockfd = 0;
		}
		return CSP_ERR_INVAL;
	}

	if (ifname == NULL) {
		ifname = CSP_IF_KISS_DEFAULT_NAME;
	}

	pts_context_t * ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		pthread_attr_destroy(&attr);
		if (ifconf->sockfd > 0) {
			close(ifconf->sockfd);
			ifconf->sockfd = 0;
		}
		return CSP_ERR_NOMEM;
	}

	strncpy(ctx->name, ifname ? ifname : "PTS", sizeof(ctx->name) - 1);

	ctx->iface.name = ctx->name;
	ctx->iface.addr = addr;
	ctx->iface.driver_data = ifconf;          /* points to configuration struct */
	ctx->iface.interface_data = &ctx->ifdata; /* points to KISS interface data within ctx */
	ctx->iface.nexthop = csp_if_pts_tx;       /* transmit function */

	memset(&ctx->ifdata, 0, sizeof(ctx->ifdata));
	//	ctx->ifdata.tx_func = pts_driver_tx;
	ctx->ifdata.rx_mode = KISS_MODE_NOT_STARTED;
	ctx->ifdata.rx_packet = NULL;

	csp_iflist_add(&ctx->iface);

	if (return_iface) {
		*return_iface = &ctx->iface;
	}

	ret = pthread_create(&ifconf->server_handle, &attr, csp_if_pts_rx_loop, &ctx->iface);
	if (ret != 0) {
		csp_print("PTS: pthread_create failed: %s\n", strerror(ret));
		free(ctx);
		pthread_attr_destroy(&attr);
		return CSP_ERR_INVAL;
	}

	pthread_attr_destroy(&attr);

	return CSP_ERR_NONE;
}
/* ---------------- TERMIOS SEND ---------------- */

int csp_if_pts_send_termios_config(csp_if_pts_conf_t * ifconf, uint16_t port, uint32_t baudrate) {
	if (ifconf == NULL || ifconf->sockfd <= 0) {
		csp_print("PTS: invalid socket\n");
		return -1;
	}

	termios2_packet_t termios2 = {0};
	termios2.c_iflag = 0;
	termios2.c_oflag = 0;
	termios2.c_cflag = B9600 | CS8 | CREAD | CLOCAL;
	termios2.c_lflag = 0;
	termios2.c_line = 0;
	memset(termios2.c_cc, 0, sizeof(termios2.c_cc));
	termios2.c_ispeed = baudrate;
	termios2.c_ospeed = baudrate;

	uint32_t startword = 0xDEADBEEF;
	const char startconfigword[7] = {'t', 'e', 'r', 'm', 'i', 'o', 's'};

	uint8_t packet[sizeof(startword) + 7 + sizeof(port) + sizeof(termios2)];
	uint8_t * p = packet;

	memcpy(p, &startword, sizeof(startword));
	p += sizeof(startword);
	memcpy(p, startconfigword, sizeof(startconfigword));
	p += sizeof(startconfigword);
	memcpy(p, &port, sizeof(port));
	p += sizeof(port);
	memcpy(p, &termios2, sizeof(termios2));
	p += sizeof(termios2);

	size_t packet_len = p - packet;
	ssize_t sent = send(ifconf->sockfd, packet, packet_len, MSG_NOSIGNAL);

	if (sent != (ssize_t)packet_len) {
		csp_print("PTS: failed to send termios config (%zd/%zu): %s\n",
				  sent, packet_len, strerror(errno));
		return -1;
	}

	csp_print("PTS: termios config sent (%zu bytes)\n", packet_len);
	return 0;
}
