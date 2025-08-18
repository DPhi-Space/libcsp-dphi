#include <csp/interfaces/csp_if_tun.h>
#include <csp/csp.h>
#include <csp/csp_id.h>
#include <csp/csp_hooks.h>
#include "csp_macro.h"
#include <ascon/crypto_aead.h>
#include <sys/random.h>

#define ASCON_NONCE_BYTES 16

int csp_crypto_decrypt(uint8_t * ciphertext_in, uint8_t ciphertext_len, uint8_t * msg_out) {
	// Prepare buffer for 16bytes Nonce
	unsigned char n[ASCON_NONCE_BYTES];
	memset(n, 0, ASCON_NONCE_BYTES);

	if (ciphertext_len < ASCON_NONCE_BYTES) {
		csp_print("The incoming encrypted message is shorter than expected, will skip decryption");
		memcpy(ciphertext_in, msg_out, ciphertext_len);
		return ciphertext_len;
	}
	// Copy Nonce from incoming message
	memcpy(n, ciphertext_in, ASCON_NONCE_BYTES);
	// Adapt lengths and move pointer
	ciphertext_in += ASCON_NONCE_BYTES;
	ciphertext_len -= ASCON_NONCE_BYTES;

	// TODO: Get key from elsewhere ?
  	unsigned char k[16] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15};
	unsigned long long alen = 0;
	unsigned long long mlen = 0;
	int result = 0;

	// Ascon decryption and get result
  	result |= crypto_aead_decrypt(msg_out, &mlen, (void*)0, ciphertext_in, ciphertext_len, NULL, alen, n, k);
	if(result) {
		csp_print("Error in decryption... Error : %i\n", result);
		// As there was an error but no means to tell CSP, we can copy original message directly
		ciphertext_in -= ASCON_NONCE_BYTES;
		ciphertext_len += ASCON_NONCE_BYTES;
		memcpy(ciphertext_in, msg_out, ciphertext_len);
		return ciphertext_len;
	}

  	return mlen;
}

int csp_crypto_encrypt(uint8_t * msg_begin, uint8_t msg_len, uint8_t * ciphertext_out) {
	// Prepare the buffer for Nonce
	unsigned char n[ASCON_NONCE_BYTES];
	memset(n, 0, ASCON_NONCE_BYTES);

	// TODO: For now getrandom is ok but need to investigate to have hardware randomness
	ssize_t random_result = getrandom(n, ASCON_NONCE_BYTES, 0);
    if (random_result != (ssize_t)ASCON_NONCE_BYTES) {
        return -1; // Failed to read NONCE_SIZE
	}

	// Copy Nonce at the beginning of the message
	memcpy(ciphertext_out, n, ASCON_NONCE_BYTES);
	ciphertext_out += ASCON_NONCE_BYTES;

	// TODO: Get key from elsewhere ?
  	unsigned char k[16] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15};
	unsigned long long alen = 0;
	unsigned long long clen = 0;
	int result = 0;

	// TODO: Check on packet limit size ?
	result |= crypto_aead_encrypt(ciphertext_out, &clen, msg_begin, msg_len, NULL, alen, (void*)0, n, k);
	if(result) {
		// No ways to tell CSP there was an error, we then return the unencrypted frame
		ciphertext_out -= ASCON_NONCE_BYTES;
		memset(ciphertext_out, 0, ASCON_NONCE_BYTES);

		memcpy(msg_begin, ciphertext_out, msg_len);
		csp_print("Error in encryption... Error : %i\n", result);
		return msg_len;
	}

	// Add the prepended Nonce length
	clen += ASCON_NONCE_BYTES;
	return clen;
}

static int csp_if_tun_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {

	csp_if_tun_conf_t * ifconf = iface->driver_data;

	/* Allocate new frame */
	csp_packet_t * new_packet = csp_buffer_get_always();
	if (new_packet == NULL) {
		csp_buffer_free(packet);
		return CSP_ERR_NONE;
	}

	if (packet->id.dst == ifconf->tun_src) {

		/**
		 * Incomming tunnel packet
		 */
		//csp_hex_dump("incoming packet", packet->data, packet->length);

		csp_id_setup_rx(new_packet);

#if 1
		int length = csp_crypto_decrypt(packet->data, packet->length, new_packet->frame_begin);
		if (length < 0) {
			csp_buffer_free(new_packet);
			csp_buffer_free(packet);
			iface->rx_error++;
			return CSP_ERR_NONE;
		} else {
			new_packet->frame_length = length;
		}
#else
		/* Decapsulate */
		memcpy(new_packet->frame_begin, packet->data, packet->length);
		new_packet->frame_length = packet->length;
#endif

		/* Now free old packet */
		csp_buffer_free(packet);

		//csp_hex_dump("new frame", new_packet->frame_begin, new_packet->frame_length + 16);

		csp_id_strip(new_packet);

		//csp_hex_dump("new packet", new_packet->data, new_packet->length);

		/* Send new packet */
		csp_qfifo_write(new_packet, iface, NULL);

	} else {

		/**
		 * Outgoing tunnel packet
		 */

		//csp_hex_dump("packet", packet->data, packet->length);

		/* Apply CSP header */
		csp_id_prepend(packet);

		//csp_hex_dump("outgoing frame", packet->frame_begin, packet->frame_length);

		/* Create tunnel header */
		new_packet->id.dst = ifconf->tun_dst;
		new_packet->id.src = ifconf->tun_src;
		new_packet->id.sport = 0;
		new_packet->id.dport = 0;
		new_packet->id.pri = packet->id.pri;
		new_packet->length = packet->frame_length;

#if 1
		/* Encrypt */
		new_packet->length = csp_crypto_encrypt(packet->frame_begin, packet->frame_length, new_packet->data);
#else
		/* Encapsulate */
		memcpy(new_packet->data, packet->frame_begin, packet->frame_length);
#endif

		/* Free old packet */
		csp_buffer_free(packet);

		//csp_hex_dump("outgoing new packet", new_packet->data, new_packet->length);

		/* Apply CSP header */
		csp_id_prepend(new_packet);

		//csp_hex_dump("outgoing new frame", new_packet->frame_begin, new_packet->frame_length);

		/* Send new packet */
		csp_qfifo_write(new_packet, iface, NULL);

	}

	return CSP_ERR_NONE;

}

void csp_if_tun_init(csp_iface_t * iface, csp_if_tun_conf_t * ifconf) {

	iface->driver_data = ifconf;

	/* Register interface */
	iface->name = "TUN",
	iface->nexthop = csp_if_tun_tx,
	csp_iflist_add(iface);

}
