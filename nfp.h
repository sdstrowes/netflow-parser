#ifndef __IPFIX_H_
#define __IPFIX_H_

struct template
{
	uint16_t type;
	uint16_t length;
};

struct ipfix_header
{
        uint16_t version;
        uint16_t rcount;
	uint32_t uptime;
        uint32_t export_ts;
        uint32_t seq_no;
        uint32_t obs_id;
} __attribute__((packed));

struct ipfix_set_header
{
	uint16_t set_id;
	uint16_t length;
} __attribute__((packed));

struct netflow_opts_template_header
{
	uint16_t id;
	uint16_t scope_len;
	uint16_t opts_len;
};

struct ipfix_record_header
{
	uint16_t id;
	uint16_t field_count;
} __attribute__((packed));

struct ipfix_field_spec
{
	uint16_t ie_id;
	uint16_t length;
} __attribute__((packed));

// https://tools.ietf.org/html/rfc3954#section-8
const int nf_type_str_max = 80;
static const char* nf_type_str[] = {
// [0]:
"", "IN_BYTES", "IN_PKTS", "FLOWS",
// [4]:
"PROTOCOL", "TOS", "TCP_FLAGS", "L4_SRC_PORT",
// [8]:
"IPV4_SRC_ADDR", "SRC_MASK", "INPUT_SNMP", "L4_DST_PORT",
// [12]:
"IPV4_DST_ADDR", "DST_MASK", "OUTPUT_SNMP", "IPV4_NEXT_HOP",
// [16]:
"SRC_AS", "DST_AS", "BGP_IPV4_NEXT_HOP", "MUL_DST_PKTS",
// [20]:
"MUL_DST_BYTES", "LAST_SWITCHED", "FIRST_SWITCHED", "OUT_BYTES",
// [24]:
"OUT_PKTS", "", "", "IPV6_SRC_ADDR",
// [28]:
"IPV6_DST_ADDR", "IPV6_SRC_MASK", "IPV6_DST_MASK", "IPV6_FLOW_LABEL",
// [32]:
"ICMP_TYPE", "MUL_IGMP_TYPE", "SAMPLING_INTERVAL", "SAMPLING_ALGORITHM",
// [36]:
"FLOW_ACTIVE_TIMEOUT", "FLOW_INACTIVE_TIMEOUT", "ENGINE_TYPE", "ENGINE_ID",
// [40]:
"TOTAL_BYTES_EXP", "TOTAL_PKTS_EXP", "TOTAL_FLOWS_EXP", "",
// [44]:
"", "", "MPLS_TOP_LABEL_TYPE", "MPLS_TOP_LABEL_IP_ADDR",
// [48]:
"FLOW_SAMPLER_ID", "FLOW_SAMPLER_MODE", "FLOW_SAMPLER_RANDOM_INTERVAL", "",
// [52]:
"", "", "", "DST_TOS",
// [56]:
"SRC_MAC", "DST_MAC", "SRC_VLAN", "DST_VLAN",
// [60]:
"IP_PROTOCOL_VERSION", "DIRECTION", "IPV6_NEXT_HOP", "BGP_IPV6_NEXT_HOP",
// [64]:
"IPV6_OPTION_HEADERS", "", "", "",
// [68]:
"", "", "MPLS_LABEL_1", "MPLS_LABEL_2",
// [72]:
"MPLS_LABEL_3", "MPLS_LABEL_4", "MPLS_LABEL_5", "MPLS_LABEL_6",
// [76]:
"MPLS_LABEL_7", "MPLS_LABEL_8", "MPLS_LABEL_9", "MPLS_LABEL_10"
};


void print_hex(void *, int, int);
void print_help(char *);

#endif

