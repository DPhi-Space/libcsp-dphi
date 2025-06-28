#ifndef __AUTOCONFIG_H
#define __AUTOCONFIG_H

//TODO: you need to port this to the MSP... we don't have any queue / semaphore / etc
//#cmakedefine01 CSP_POSIX
//#cmakedefine01 CSP_ZEPHYR
//#cmakedefine01 CSP_FREERTOS

//#cmakedefine01 CSP_HAVE_STDIO
//#cmakedefine01 CSP_ENABLE_CSP_PRINT
//#cmakedefine01 CSP_PRINT_STDIO

//#cmakedefine01 CSP_REPRODUCIBLE_BUILDS

//TODO: define the following
//#cmakedefine CSP_QFIFO_LEN @CSP_QFIFO_LEN@
#define CSP_QFIFO_LEN 16
//#cmakedefine CSP_PORT_MAX_BIND @CSP_PORT_MAX_BIND@
#define CSP_PORT_MAX_BIND 2
//#cmakedefine CSP_CONN_RXQUEUE_LEN @CSP_CONN_RXQUEUE_LEN@
#define CSP_CONN_RXQUEUE_LEN 4
//#cmakedefine CSP_CONN_MAX @CSP_CONN_MAX@
#define CSP_CONN_MAX 2
//#cmakedefine CSP_BUFFER_SIZE @CSP_BUFFER_SIZE@
#define CSP_BUFFER_SIZE 128
//#cmakedefine CSP_BUFFER_COUNT @CSP_BUFFER_COUNT@
#define CSP_BUFFER_COUNT 8
//#cmakedefine CSP_RDP_MAX_WINDOW @CSP_RDP_MAX_WINDOW@
#define CSP_RDP_MAX_WINDOW 8 // check this if you use RDP
//#cmakedefine CSP_RTABLE_SIZE @CSP_RTABLE_SIZE@
#define CSP_RTABLE_SIZE 4

#define CSP_FREERTOS_DPHI 1
//#cmakedefine01 CSP_USE_RDP
//#cmakedefine01 CSP_USE_HMAC
//#cmakedefine01 CSP_USE_PROMISC
//#cmakedefine01 CSP_USE_RTABLE
#define CSP_USE_RTABLE 1
//#cmakedefine01 CSP_BUFFER_ZERO_CLEAR
#define CSP_BUFFER_ZERO_CLEAR 1

//#cmakedefine01 CSP_HAVE_LIBSOCKETCAN
//#cmakedefine01 CSP_HAVE_LIBZMQ

//#cmakedefine01 CSP_FIXUP_V1_ZMQ_LITTLE_ENDIAN

typedef uint8_t csp_bin_sem_t; // Dummy definition


#endif
