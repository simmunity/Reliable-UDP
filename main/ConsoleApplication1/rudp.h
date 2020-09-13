#ifndef RUDP_PROTO_H
#define	RUDP_PROTO_H

#define RUDP_VERSION	1	/* Protocol version */
#define RUDP_MAXPKTSIZE 1000	/* Number of data bytes that can sent in a packet, RUDP header not included */
#define RUDP_MAXRETRANS 5	/* Max. number of retransmissions */
#define RUDP_TIMEOUT	2000	/* Timeout for the first retransmission in milliseconds */
#define RUDP_WINDOW	3	/* Max. number of unacknowledged packets that can be sent to the network*/

/* Packet types */

#define RUDP_DATA	1
#define RUDP_ACK	2
#define RUDP_SYN	4
#define RUDP_FIN	5

/*
 * Sequence numbers are 32-bit integers operated on with modular arithmetic.
 * These macros can be used to compare sequence numbers.
 */

#define	SEQ_LT(a,b)	((short)((a)-(b)) < 0)
#define	SEQ_LEQ(a,b)	((short)((a)-(b)) <= 0)
#define	SEQ_GT(a,b)	((short)((a)-(b)) > 0)
#define	SEQ_GEQ(a,b)	((short)((a)-(b)) >= 0)

/* RUDP packet header */

#ifdef _WIN32
  #pragma pack(push)
  #pragma pack(1)
  typedef struct rudp_hdr_t {
    uint16_t version;
    uint16_t type;
    uint32_t seqno;
  }rudp_hdr;
  #pragma pack(pop)

#else
  typedef struct rudp_hdr_t {
    uint16_t version;
    uint16_t type;
    uint32_t seqno;
}rudp_hdr __attribute__ ((packed));
#endif

#endif /* RUDP_PROTO_H */
