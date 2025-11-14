#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

#include <string.h> 
#include <stdlib.h> 

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/* --- Function prototypes --- */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
void send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                           struct sr_if *iface, uint8_t type, uint8_t code);
void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface);
void send_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                    char *iface_name, uint8_t *dest_mac);
void send_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                    char *iface_name, uint8_t *dest_mac);
void send_arp_request(struct sr_instance *sr, struct sr_if *iface, uint32_t ip);

/* --------------------------- */

typedef enum {
    HDR_ETHERNET,
    HDR_IP,
    HDR_ICMP,
    HDR_ARP
} header_type_t;

/*---------------------------------------------------------------------
 * Method: get_packet_header()
 *
 * This method returns a pointer to the requested header type within a raw packet.
 *
 * Parameters:
 *   packet -- pointer to the received Ethernet frame
 *   type   -- header type to extract (HDR_ETHERNET, HDR_IP, HDR_ICMP, HDR_ARP)
 *---------------------------------------------------------------------*/
void* get_packet_header(uint8_t *packet, header_type_t type) {
    if (!packet) return NULL;

    switch (type) {
        case HDR_ETHERNET:
            return (void *)packet;

        case HDR_IP:
            return (void *)(packet + sizeof(sr_ethernet_hdr_t));

        case HDR_ICMP:
            return (void *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        case HDR_ARP:
            return (void *)(packet + sizeof(sr_ethernet_hdr_t));

        default:
            return NULL;
    }
} /* -- get_packet_header -- */

/*---------------------------------------------------------------------
 * Method: build_ethernet_header(sr_ethernet_hdr_t *eth_hdr,
                                struct sr_if *iface,
                                const uint8_t *dest_mac,
                                uint16_t ether_type,
                                int is_broadcast)
 *
 * This method builds a generic Ethernet header for any outgoing packet type (IP or ARP).
 * It sets:
 *   - Destination MAC: provided (unicast), broadcast, or all zeros (for ARP request)
 *   - Source MAC: interface’s hardware address
 *   - EtherType: protocol type (e.g., ethertype_ip or ethertype_arp)
 *
 * Parameters:
 *   eth_hdr   -- pointer to the Ethernet header to populate
 *   iface     -- outgoing interface whose MAC is used as source
 *   dest_mac  -- destination MAC address; if NULL:
 *                  - uses broadcast (FF:FF:FF:FF:FF:FF) if is_broadcast = 1
 *                  - uses all zeros if is_broadcast = 0 (e.g., ARP request)
 *   ether_type -- protocol type (e.g., htons(ethertype_ip), htons(ethertype_arp))
 *   is_broadcast -- 1 for broadcast dest, 0 to zero-fill dest if dest_mac == NULL
 *---------------------------------------------------------------------*/
void build_ethernet_header(sr_ethernet_hdr_t *eth_hdr,
                           struct sr_if *iface,
                           const uint8_t *dest_mac,
                           uint16_t ether_type,
                           int is_broadcast) {
    /* REQUIRES */
    assert(eth_hdr);
    assert(iface);

    if (dest_mac) {
        memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    } else if (is_broadcast) {
        memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);  /* Broadcast */
    } else {
        memset(eth_hdr->ether_dhost, 0x00, ETHER_ADDR_LEN);  /* Unknown dest */
    }

    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = ether_type;
} /* build_ethernet_header */

/*---------------------------------------------------------------------
 * Method: build_ip_header(sr_ip_hdr_t *ip_hdr,
                          uint32_t src_ip,
                          uint32_t dst_ip,
                          uint16_t payload_len,
                          uint8_t protocol,
                          uint8_t ttl)
 *
 * This method populates an IPv4 header for an outgoing packet.
 * Supports sending ICMP or other IP payloads, setting source/destination,
 * TTL, protocol, length, and computing the checksum.
 *
 * Parameters:
 *   ip_hdr       -- pointer to the IP header to fill
 *   src_ip       -- source IP address (host order)
 *   dst_ip       -- destination IP address (host order)
 *   payload_len  -- length of payload after IP header (e.g., ICMP)
 *   protocol     -- next protocol (e.g., ip_protocol_icmp)
 *   ttl          -- TTL to use (default 64 recommended)

 *---------------------------------------------------------------------*/
void build_ip_header(sr_ip_hdr_t *ip_hdr,
                     uint32_t src_ip,
                     uint32_t dst_ip,
                     uint16_t payload_len,
                     uint8_t protocol,
                     uint8_t ttl) {
    assert(ip_hdr);

    ip_hdr->ip_v = 4;           /* IPv4 */
    ip_hdr->ip_hl = 5;          /* header length = 5 words = 20 bytes */
    ip_hdr->ip_tos = 0;         /* default TOS */
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + payload_len);
    ip_hdr->ip_id = 0;           /* not fragmented */
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = ttl;       /* TTL */
    ip_hdr->ip_p = protocol;    /* next protocol */
    ip_hdr->ip_src = src_ip;
    ip_hdr->ip_dst = dst_ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
} /* -- build_ip_header -- */

/*---------------------------------------------------------------------
 * Method: build_icmp_t3_header()
 * Scope:  Utility helper
 *
 * Description:
 *   Populates an ICMP type 3/11 header (ICMP "destination unreachable" or
 *   "time exceeded") for an outgoing packet.
 *
 * Parameters:
 *   icmp_hdr    -- pointer to ICMP header to fill
 *   type        -- ICMP type (e.g., 3 for unreachable, 11 for time exceeded)
 *   code        -- ICMP code
 *   original_ip -- pointer to original IP header that caused ICMP
 *   data_len    -- number of bytes to copy from original IP header + payload (usually 28 bytes)
 *
 * Returns:
 *   None
 *
 * Notes:
 *   - Computes ICMP checksum automatically.
 *---------------------------------------------------------------------*/
void build_icmp_t3_header(sr_icmp_t3_hdr_t *icmp_hdr,
                          uint8_t type,
                          uint8_t code,
                          const sr_ip_hdr_t *original_ip,
                          size_t data_len) {
    /* REQUIRES */
    assert(icmp_hdr);
    assert(original_ip);

    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;

    /* copy original IP header + first 8 bytes of payload */
    memcpy(icmp_hdr->data, original_ip, data_len);

    /* compute checksum */
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
} /* -- build_icmp_t3_header -- */

/*---------------------------------------------------------------------
 * Method: send_or_queue_packet(struct sr_instance *sr, uint32_t next_hop,
                                uint8_t *packet, unsigned int len,
                                struct sr_if *iface)
 *
 * This method attempts to send a packet by performing an ARP cache lookup for
 * the destination IP. If the MAC address is known, sends immediately.
 * Otherwise, queues the packet in the ARP request queue and triggers ARP request handling.
 *
 * Arguments:
 *   sr       -- router instance
 *   next_hop -- destination IP address (in network byte order)
 *   packet   -- pointer to the Ethernet frame to send
 *   len      -- total length of the packet
 *   iface    -- outgoing interface to send the packet on
 *---------------------------------------------------------------------*/
void send_or_queue_packet(struct sr_instance *sr, uint32_t next_hop,
                          uint8_t *packet, unsigned int len,
                          struct sr_if *iface) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    /* attempt to find ARP entry for destination IP */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop);
    /* if found */
    if (arp_entry) {
        /* MAC address known — send immediately */
        send_ip_packet(sr, packet, len, iface->name, arp_entry->mac);
        free(arp_entry);
    } else {
        /* MAC unknown — queue in ARP request list */
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop,
                                                     packet, len, iface->name);
        handle_arpreq(sr, req);
    }
} /* -- send_or_queue_packet -- */


/*---------------------------------------------------------------------
 * Method: send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                                 struct sr_if *iface, uint8_t type, uint8_t code)
 *
 * This method constructs and sends an ICMP "Destination Unreachable" message
 * (type 3) back to the source of a received IP packet. This is used when a
 * packet cannot be delivered because there is no route, the port is closed,
 * or other unreachable conditions occur.
 *
 * Parameters:
 *  sr      -- router instance
 *  packet  -- pointer to the original received Ethernet frame
 *  len     -- length of the original packet
 *  iface   -- outgoing interface (to send ICMP from)
 *  type    -- ICMP type (typically 3)
 *  code    -- ICMP code (0, 1, or 3)
 *---------------------------------------------------------------------*/
void send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                           struct sr_if *iface, uint8_t type, uint8_t code) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    /* get original IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)get_packet_header(packet, HDR_IP);

    /* allocate new packet for ethernet + IP + ICMP type 3 */
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = malloc(icmp_len);
    if (!icmp_packet) return;

    /* ethernet: dest: (will ARP later), src: our interface, type: IP */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    build_ethernet_header(eth_hdr, iface, NULL, htons(ethertype_ip), 0);

    /* IP */
    sr_ip_hdr_t *new_ip = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    build_ip_header(new_ip,
                    iface->ip,       /* source = outgoing interface */
                    ip_hdr->ip_src,  /* destination = original sender */
                    sizeof(sr_icmp_t3_hdr_t), /* payload = ICMP header+data */
                    ip_protocol_icmp,
                    64);             /* default TTL */


    /* ICMP header */
    sr_icmp_t3_hdr_t *icmp = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    build_icmp_t3_header(icmp, type, code, ip_hdr, ICMP_DATA_SIZE);

    /* Send via ARP resolution */
    send_or_queue_packet(sr, new_ip->ip_dst, icmp_packet, icmp_len, iface);
    free(icmp_packet);
} /* -- send_icmp_unreachable -- */

/*---------------------------------------------------------------------
 * Method: send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet,
 *                                 struct sr_if *iface)
 * Scope:  Local (called by forwarding logic when TTL reaches 0)
 *
 * This method constructs and sends an ICMP Time Exceeded message (Type 11, Code 0)
 * to the source of an IP packet whose TTL expired during forwarding.
 *
 * The function builds a new Ethernet + IP + ICMP Type 11 packet and either
 * sends it directly if an ARP entry exists or queues it for ARP resolution.
 *
 * Parameters:
 *   sr     - Pointer to the router instance (contains interfaces and ARP cache)
 *   packet - The original IP packet that caused the TTL expiration
 *   iface  - The outgoing interface used to send the ICMP error message
 *---------------------------------------------------------------------*/
void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    /* extract IP header from the original packet */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)get_packet_header(packet, HDR_IP);
    /* allocate new packet for ethernet + IP + ICMP type 11 */
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = malloc(icmp_len);
    if (!icmp_packet) return;

    /* ethernet: source: this interface, destination: filled after ARP lookup, type: IP */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    build_ethernet_header(eth_hdr, iface, NULL, htons(ethertype_ip), 0);

    /* IP: src = this interface, dst = original sender, TTL = 64, protocol = ICMP, payload = ICMP type 11*/
    sr_ip_hdr_t *new_ip = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    build_ip_header(new_ip,
                    iface->ip,       /* source = outgoing interface */
                    ip_hdr->ip_src,  /* destination = original sender */
                    sizeof(sr_icmp_t3_hdr_t), /* payload = ICMP header+data */
                    ip_protocol_icmp,
                    64);             /* default TTL */

    sr_icmp_t3_hdr_t *icmp = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    build_icmp_t3_header(icmp, 11, 0, ip_hdr, ICMP_DATA_SIZE);

    /* attempt to send or queue the ICMP packet */
    send_or_queue_packet(sr, new_ip->ip_dst, icmp_packet, icmp_len, iface);
    free(icmp_packet);
} /* -- send_icmp_time_exceeded -- */

/*---------------------------------------------------------------------
 * Method: send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet,
 *                              unsigned int len, char *iface)
 * Scope:  Local (called by handle_ip_packet() for ICMP Echo Requests)
 *
 * This method constructs and sends an ICMP Echo Reply in response to an incoming
 * ICMP Echo Request (ping). Modifies the incoming packet in-place:
 *   - Swaps source and destination IP addresses
 *   - Swaps Ethernet source and destination MAC addresses
 *   - Changes ICMP type/code to Echo Reply (Type 0, Code 0)
 *   - Recalculates ICMP and IP checksums
 *
 * Parameters:
 *   sr      - Pointer to the router instance (contains interfaces, ARP cache)
 *   packet  - Pointer to the received Ethernet frame containing the ICMP request
 *   len     - Total length of the received packet in bytes
 *   iface   - Name of the interface on which the packet should be sent
 *---------------------------------------------------------------------*/
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *iface) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    /* extract headers */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)get_packet_header(packet, HDR_ETHERNET);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)get_packet_header(packet, HDR_IP);
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)get_packet_header(packet, HDR_ICMP);

    /* swap source and destination IP addresses */
    uint32_t tmp_ip = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = tmp_ip;

    /* swap ethernet source and destination MAC addresses */
    uint8_t tmp_mac[ETHER_ADDR_LEN];
    memcpy(tmp_mac, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, tmp_mac, ETHER_ADDR_LEN);

    /* change ICMP type to echo reply */
    icmp_hdr->icmp_type = 0; /* echo reply */
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0; /* clear before computing checksum */
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

    /* recalculate IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* send the modified packet back to the source */
    sr_send_packet(sr, packet, len, iface);
} /* -- send_icmp_echo_reply -- */

/*---------------------------------------------------------------------
 * Method: send_ip_packet(struct sr_instance *sr, uint8_t *packet,
 *                        unsigned int len, char *iface_name, uint8_t *dest_mac)
 * Scope:  Local (called by IP forwarding logic)
 *
 * This method sends an IP packet on the specified interface to the given
 * destination MAC address. Updates the Ethernet header with the correct 
 * source and destination MACs before transmission.
 *
 * This function does not modify the IP header or recalculate checksums
 * — it assumes the packet is valid and ready to send.
 *
 * Parameters:
 *   sr         - Pointer to the router instance (contains interfaces).
 *   packet     - Pointer to the full Ethernet frame containing the IP packet.
 *   len        - Length of the packet in bytes.
 *   iface_name - Name of the outgoing interface to send the packet on.
 *   dest_mac   - Destination MAC address (6 bytes) for the next hop.
 *---------------------------------------------------------------------*/
void send_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                    char *iface_name, uint8_t *dest_mac) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface_name);
    assert(dest_mac);

    /* lookup outgoing interface */
    struct sr_if *iface = sr_get_interface(sr, iface_name);
    if (!iface) {
        fprintf(stderr, "send_ip_packet: iface %s not found\n", iface_name);
        return;
    }

    /* ensure packet has enough bytes for ethernet + IP headers */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "send_ip_packet: packet too short\n");
        return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)get_packet_header(packet, HDR_ETHERNET);
    /* ethernet: destination = next-hop, source = this interface, type = IP */
    build_ethernet_header(eth_hdr, iface, dest_mac, htons(ethertype_ip), 0);

    /* transmit the packet */
    sr_send_packet(sr, packet, len, iface_name);

    printf("*** forward: sent packet on %s to %02x:%02x:%02x:%02x:%02x:%02x\n",
           iface_name,
           dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    fflush(stdout);
} /* -- send_ip_packet -- */

/*---------------------------------------------------------------------
 * Method: send_arp_request(struct sr_instance *sr, struct sr_if *iface, uint32_t ip)
 * Scope:  Local (called by ARP cache and forwarding logic)
 *
 * This method constructs and sends an ARP request on the specified interface to
 * resolve the given IP address. This function is typically called when an 
 * outgoing packet requires a MAC address that is not yet in the ARP cache.
 *
 * The Ethernet frame is broadcast (FF:FF:FF:FF:FF:FF), and the ARP request header 
 * specifies the sender’s hardware/IP information.
 *
 * Parameters:
 *   sr     - Pointer to the router instance (used to send packets)
 *   iface  - The outgoing interface on which to send the request
 *   ip     - The target IP address to resolve
 *---------------------------------------------------------------------*/
void send_arp_request(struct sr_instance *sr, struct sr_if *iface, uint32_t ip) {
    /* REQUIRES */
    assert(sr);
    assert(iface);

    /* allocate memory for ethernet + ARP headers */
    unsigned int pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *pkt = malloc(pkt_len);
    if (!pkt) return;

    sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)pkt;
    sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    /* ethernet: dst = broadcast, src = iface MAC, type = ARP */
    build_ethernet_header(eth, iface, NULL, htons(ethertype_arp), 1);

    /* ARP request */
    arp->ar_hrd = htons(arp_hrd_ethernet); /* Hardware = Ethernet */
    arp->ar_pro = htons(ethertype_ip);     /* Protocol = IPv4 */
    arp->ar_hln = ETHER_ADDR_LEN;          /* Hardware length = 6 */
    arp->ar_pln = 4;                       /* Protocol length = 4 */
    arp->ar_op = htons(arp_op_request);    /* Operation = Request */

    /* sender: router’s MAC/IP */
    memcpy(arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp->ar_sip = iface->ip;

    /* target: unknown MAC, target IP */
    memset(arp->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp->ar_tip = ip;

    /* transmit ARP request and clean up */
    sr_send_packet(sr, pkt, pkt_len, iface->name);
    free(pkt);

    printf("*** Sent ARP request for ip %u on %s\n", ntohl(ip), iface->name);
    fflush(stdout);
} /* -- send_arp_request -- */

/*---------------------------------------------------------------------
 * Method: handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
 * Scope: Local (called by ARP cache logic when processing pending requests)
 *
 * This method handles pending ARP requests that are waiting for resolution in the
 * ARP cache. This function is typically called periodically by the ARP cache sweep
 * routine (sr_arpcache_sweepreqs).
 *
 * Parameters:
 *   sr   - Pointer to the router instance (contains ARP cache and interfaces).
 *   req  - Pointer to the ARP request entry to handle.
 *          Contains target IP, retry info, and queued packets.
 *---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
  /* check if time to retry (at least 1 second since last attempt) */
    if (difftime(time(NULL), req->sent) > 1.0) {
      /* exceeded max retries — give up and send ICMP errors */
      if (req->times_sent >= 5) {
        /* send ICMP host unreachable for each queued packet */
        struct sr_packet *pkt = req->packets;
        while (pkt) {
          struct sr_if *iface = sr_get_interface(sr, pkt->iface);
          /* type 3, code 1 = host unreachable */
          send_icmp_unreachable(sr, pkt->buf, pkt->len, iface, 3, 1); /* host unreachable */
          pkt = pkt->next;
        }
        /* remove ARP request entry from cache */
        sr_arpreq_destroy(&sr->cache, req);
      } else {
        /* retry sending ARP request (hasn't reached 5 attempts)*/
        struct sr_if *iface = sr_get_interface(sr, req->packets->iface);
        /* send new ARP request for the unresolved IP */
        if (iface) send_arp_request(sr, iface, req->ip);
        /* update timestamp and increment retry count */
        req->sent = time(NULL);
        req->times_sent++;
      }
    }
} /* -- handle_arpreq -- */

 /*---------------------------------------------------------------------
 * Method: longest_prefix_match(struct sr_instance *sr, uint32_t dest_ip)
 * Scope:  Local (routing lookup helper)
 *
 * Performs a longest-prefix match (LPM) search in the router’s routing 
 * table to determine the best route for a given destination IP.
 *
 * The function iterates through all routing table entries and selects the
 * entry whose subnet mask yields the longest matching prefix with the
 * destination IP address.
 *
 * If multiple entries match, the one with the largest mask (most bits set)
 * is chosen. Returns NULL if no entries match.
 *
 * Parameters:
 *   sr       - Pointer to the router instance containing the routing table.
 *   dest_ip  - Destination IPv4 address (in network byte order) to look up.
 *
 * Returns:
 *   Pointer to the best matching routing table entry (struct sr_rt),
 *   or NULL if no route matches the destination IP.
 *---------------------------------------------------------------------*/
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip) {
  struct sr_rt* best = NULL;
  struct sr_rt* rt_walker = sr->routing_table;
  /* iterate through all routing table entries and check for matches */
  while (rt_walker) {
    /* compare masked destination IP with routing entry's destination */
    if ((dest_ip & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
      /* if this is the first match, or has a longer mask, update best */
      if (!best || (ntohl(rt_walker->mask.s_addr) > ntohl(best->mask.s_addr))) {
        best = rt_walker;
      }
    }
    /* move to next routing table entry */
    rt_walker = rt_walker->next;
  }
  return best;
} /* -- longest_prefix_match -- */

 /*---------------------------------------------------------------------
 * Method: handle_arp_packet(struct sr_instance *sr, uint8_t *packet,
 *                           unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method handles incoming ARP packets (both requests and replies)
 *
 * Parameters:
 *   sr        - Pointer to the router instance containing interfaces,
 *               ARP cache, and routing information.
 *   packet    - Pointer to the received Ethernet frame containing the ARP packet.
 *   len       - Length of the received packet in bytes.
 *   interface - Name of the interface on which the packet was received.
 *---------------------------------------------------------------------*/

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet,
                       unsigned int len, char *interface) {
  /* ensure packet has full ARP header */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "ARP packet too short\n");
    return;
  }
  /* extract ethernet and ARP headers */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)get_packet_header(packet, HDR_ETHERNET);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)get_packet_header(packet, HDR_ARP);

  uint16_t arp_op = ntohs(arp_hdr->ar_op);
  struct sr_if *iface = sr_get_interface(sr, interface);

  if (!iface) {
    fprintf(stderr, "Invalid interface in handle_arp_packet\n");
    return;
  }

  /* handle ARP request */
  if (arp_op == arp_op_request) {
    /* check if this request targets one of our IP addresses */
    if (arp_hdr->ar_tip == iface->ip) {
      printf("Responding to ARP request for %s\n", interface);
      /* create ARP reply by copying request and modifying headers */
      uint8_t reply[len];
      memcpy(reply, packet, len);

      sr_ethernet_hdr_t *eth_reply = (sr_ethernet_hdr_t *)reply;
      sr_arp_hdr_t *arp_reply =
          (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));

      /* ethernet header: swap src/dst MACs */
      build_ethernet_header(eth_reply, iface, eth_hdr->ether_shost, htons(ethertype_arp), 0);
      /* ARP header: fill in reply fields */
      arp_reply->ar_op = htons(arp_op_reply);
      memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      arp_reply->ar_tip = arp_hdr->ar_sip;
      memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
      arp_reply->ar_sip = iface->ip;

      /* send ARP reply back out the same interface */
      sr_send_packet(sr, reply, len, interface);
      return;
    }
  }

  /* handle ARP reply */
  else if (arp_op == arp_op_reply) {
    printf("Received ARP reply\n");
    /* insert new mapping into ARP cache */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha,
                                               arp_hdr->ar_sip);
    /* if packets were waiting for this IP, send them now */
    if (req) {
      struct sr_packet *pkt;
      for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
        iface = sr_get_interface(sr, pkt->iface);
        if (!iface) {
            fprintf(stderr, "handle_arp_packet: interface %s not found\n", pkt->iface);
            continue;
        }
        /* fix ethernet header using send_ip_packet() */
        send_ip_packet(sr, pkt->buf, pkt->len, iface->name, arp_hdr->ar_sha);
      }
      /* clean up ARP request entry after sending queued packets */
      sr_arpreq_destroy(&(sr->cache), req);
    }
  }

  else {
    /* unknown/unsupported ARP Operation */
    printf("Unknown ARP op: %d\n", arp_op);
  }
} /* -- handle_arp_packet -- */

 /*---------------------------------------------------------------------
 * Method: handle_ip_packet(struct sr_instance *sr, uint8_t *packet,
 *                          unsigned int len, char *interface)
 * Scope:  Local (Router Packet Processing)
 *
 * This method handles incoming IP packets (either to router or to be forwarded)
 *
 * Parameters:
 *  sr        - Pointer to the router instance.
 *  packet    - Pointer to the received Ethernet frame.
 *  len       - Length of the received packet.
 *  interface - Name of the interface on which the packet was received.
 *---------------------------------------------------------------------*/

void handle_ip_packet(struct sr_instance *sr, uint8_t *packet,
                      unsigned int len, char *interface) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* extract IP header from ethernet frame */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)get_packet_header(packet, HDR_IP);
    uint32_t dest_ip = ip_hdr->ip_dst;

    /* check if the destination IP matches any router interface */
    struct sr_if *iface = sr->if_list;
    while (iface) {
        if (iface->ip == dest_ip) {
            break; /* packet is destined for this router */
        }
        iface = iface->next;
    }

    /* if packet is for the router, handle locally */
    if (iface) {
        /* ICMP packet is for the router */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            if (icmp_hdr->icmp_type == 8) { /* echo request */
                send_icmp_echo_reply(sr, packet, len, interface);
                printf("*** -> ICMP Echo Reply sent\n");
            } else {
                /* unsupported ICMP types -> send ICMP Port Unreachable */
                send_icmp_unreachable(sr, packet, len, iface, 3, 3);
            }
        } else {
            /* non-ICMP to router -> send ICMP Port Unreachable */
            send_icmp_unreachable(sr, packet, len, iface, 3, 3);
        }
        return; /* packet handled locally */
    }

    /* not destined for router, packet to be forwarded */
    struct sr_rt *rt_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
    if (!rt_entry) {
      iface = sr_get_interface(sr, interface); /* use incoming iface */
      send_icmp_unreachable(sr, packet, len, iface, 3, 0); /* net unreachable */
      return;
    }

    /* determine next-hop IP: if gw is 0 (directly connected), use destination IP */
    uint32_t next_hop_ip = (rt_entry->gw.s_addr == 0) ? ip_hdr->ip_dst : rt_entry->gw.s_addr;

    /* look up ARP entry for next hop */
    struct sr_if *out_iface = sr_get_interface(sr, rt_entry->interface);
    send_or_queue_packet(sr, next_hop_ip, packet, len, out_iface);

} /* -- handle_ip_packet -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  uint16_t type = ethertype(packet);
  printf("*** -> Received packet of length %d, type: %04x\n", len, type);
  fflush(stdout);


  /* check packet length long enough */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Packet too short for Ethernet header\n");
    return;
  }
  /* extract the header and get the EtherType*/
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  uint16_t ether_type = ntohs(eth_hdr->ether_type);

  /* check EtherType */
  switch (ether_type) {
    /* if ARP Packet */
    case ethertype_arp:
      printf("  -> ARP packet received\n");
      handle_arp_packet(sr, packet, len, interface);
      break;
    /* if IP Packet */
    case ethertype_ip:
      printf("  -> IP packet received\n");
      handle_ip_packet(sr, packet, len, interface);
      break;
    /* unknown ethertype */
    default:
      printf("  -> Unknown EtherType: 0x%04x\n", ether_type);
      break;
  }

} /* end sr_ForwardPacket */
