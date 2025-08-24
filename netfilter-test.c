#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


struct ip_hdr {
	uint8_t ver_IHL;
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_address;
	uint32_t des_address;
};

struct tcp_hdr{
	uint16_t scr_port;
	uint16_t des_port;
	uint32_t seq;
	uint32_t ack_num;
	uint8_t offset_reserved;
	uint8_t flag;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
};

struct pkt_hdr{
	struct ip_hdr ip_hdr;
	struct tcp_hdr tcp_hdr;
};

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);
		dump(data, ret);
		
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data_ptr) // void *data_ptr로 인자를 받음
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    // main에서 넘겨준 호스트 이름을 char*로 캐스팅
    char *target_host = (char *)data_ptr;
    
    // 검색할 Host 헤더 문자열을 동적으로 생성
    char host_header_to_find[256];
    snprintf(host_header_to_find, sizeof(host_header_to_find), "Host: %s", target_host);

    unsigned char *data;
    int ret = nfq_get_payload(nfa, &data);
    if (ret < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    struct ip_hdr *ip_header = (struct ip_hdr *)data;

    if (ip_header->protocol != IPPROTO_TCP) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    uint32_t ip_header_len = (ip_header->ver_IHL & 0x0F) * 4;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *)(data + ip_header_len);
    uint32_t tcp_header_len = ((tcp_header->offset_reserved & 0xF0) >> 4) * 4;

    char *http_payload = (char *)(data + ip_header_len + tcp_header_len);
    int http_payload_len = ret - (ip_header_len + tcp_header_len);

    if (http_payload_len > 0) {
        // 동적으로 생성된 문자열로 Host 헤더 검색
        if (strstr(http_payload, host_header_to_find) != NULL) {
            printf("Host '%s' found. Dropping packet.\n", target_host);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
        fprintf(stderr, "Usage: netfilter-test <host>\n");
        exit(1);
    }
    char *target_host = argv[1];
    printf("Target host to drop: %s\n", target_host);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, target_host);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

