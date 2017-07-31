#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "nfp.h"

static bool debug;

/* store global information about the templates */
static           struct template *templates;
static int       template_count = 0;
static const int template_max   = 128;

struct template *get_template(uint16_t type)
{
	int i;

	for (i = 0; i < template_count; i++) {
		if (templates[i].type == type) {
			return templates+i;
		}
	}

	return NULL;
}
/* --------------------------- */

void handle_bad_fread(gzFile file)
{
	if (gzeof(file)) {
		printf("[.EOF]\n");
		exit(EXIT_SUCCESS);
	}
	else {
		fprintf(stderr, "[.ERR] gzread: %s\n", gzerror(file, NULL));
		exit(EXIT_FAILURE);
	}
}

void print_hex(void *in, int start, int end)
{
	uint8_t *array = (uint8_t *)in;
	int i;
	printf("\n[0000] ");
	for (i = start; i < end; i++) {
		if (i > 0 && i % 8 == 0) {
			printf("\n[%04x] ", i);
		}
		uint8_t foo = array[i];
		printf("%02x ", foo);
	}
	printf("\n");
}


void print_help(char *name)
{
	printf("%s: ploughs through NetFlow v9 files\n", basename(name));
	printf("Options:\n");
	printf("	-f <file>	: Input file (required)\n");
	printf("	-d		: Turns on debugging.\n");
	printf("	-h		: Print this help then exit.\n");
}

/* This function doesn't try to mangle the data flow sets yet,
 * but should try to count how many records appear in a set
 */
int parse_flow_set(gzFile file, int id, int length)
{
	int idx = 0;
	int flowset_length = length - sizeof(struct ipfix_set_header);
	uint8_t *buffer = (uint8_t *)calloc(1, flowset_length);
	if (buffer == NULL) {
		return -1;
	}

	/* Attempt to count number of records */
	struct template *tmpl = get_template(id);
	if (tmpl != NULL) {
		int tmp = flowset_length;
		while (tmp >= tmpl->length) {
			tmp -= tmpl->length;
			idx += 1;
		}
		if (tmp > 4) {
			printf("[WARN] Unusual byte padding on flow record\n");
		}
	}
	else {
		idx = 1;
	}
	printf("[FLOW] Found %u records\n", idx);

	int l2 = gzread(file, buffer, flowset_length);
	if (l2 != flowset_length) {
		free(buffer);
		handle_bad_fread(file);
	}

	if (debug) {
		print_hex(buffer, 0, flowset_length);
	}

	free(buffer);
	return idx;
}

/* This function parses and counts the options templates,
 * but doesn't otherwise do anything with them. */
int parse_options_template_set(gzFile file, int length)
{
	printf("Found: Options Template Set, length: %u\n", length);

	int idx;
	int flowset_length = length - sizeof(struct ipfix_set_header);
	uint8_t *buffer = (uint8_t *)calloc(1, flowset_length);
	if (buffer == NULL) {
		return -1;
	}

	/* read full flowset */
	int l2 = gzread(file, buffer, flowset_length);
	if (l2 != flowset_length) {
		free(buffer);
		handle_bad_fread(file);
	}

	if (debug) {
		print_hex(buffer, 0, flowset_length);
	}

	/* attempt to count records within the set */
	idx = 0;
	int record_count = 0;
	/* '2' here is padding that might be added and is also too short to be
	 * another record */
	while (idx < (flowset_length - 2)) {
		struct netflow_opts_template_header *header = (struct netflow_opts_template_header *)buffer;
		printf("[Opts] Template ID: %u\n", htons(header->id));
		printf("[Opts] Scope len: %u\n", htons(header->scope_len));
		printf("[Opts] Opts len: %u\n", htons(header->opts_len));

		/* advance index */
		idx = idx + sizeof(struct netflow_opts_template_header) + htons(header->scope_len) + htons(header->opts_len);

		record_count++;
	}

	free(buffer);
	return record_count;
}

/* parse the template sets and store basic info about the IDs identified */
int parse_template_set(gzFile file, int length)
{
	int idx = 0;
	int record_count = 0;
	int flowset_length = length - sizeof(struct ipfix_set_header);
	uint8_t *buffer = (uint8_t *)calloc(1, flowset_length);
	if (buffer == NULL) {
		return -1;
	}

	int l2 = gzread(file, buffer, flowset_length);
	if (l2 != flowset_length) {
		free(buffer);
		handle_bad_fread(file);
	}

	if (debug) {
		print_hex(buffer, 0, flowset_length);
	}

	/* Each flowset may contain multiple template records */
	while (idx < flowset_length) {
		struct ipfix_record_header *record;
		record = (struct ipfix_record_header *)(buffer + idx);
		idx += sizeof(struct ipfix_record_header);

		/* Each template is one record; each template has multiple fields */
		printf("[TMPL] Template ID: %u; fields: %u\n", htons(record->id), htons(record->field_count));
		record_count++;

		/* Skip if we've already seen this template ID */
		struct template *tmpl = get_template(htons(record->id));
		if (tmpl != NULL) {
			printf("[SEEN] Template ID: %u (%u/%u)\n", htons(record->id), idx, flowset_length);
			idx += sizeof(struct ipfix_field_spec) * htons(record->field_count);
			continue;
		}

		/* Parse the template */
		int i;
		int data_flowset_len = 0;
		for (i = 0; i < htons(record->field_count); i++) {
			struct ipfix_field_spec *spec;
			spec = (struct ipfix_field_spec *)(buffer + idx);
			idx += sizeof(struct ipfix_field_spec);
			data_flowset_len += htons(spec->length);

			spec->ie_id = htons(spec->ie_id);
			if (spec->ie_id < nf_type_str_max && strlen(nf_type_str[spec->ie_id])) {
				printf("[%04u] IE ID: %15s (id:%4u; length:%4u)\n", i, nf_type_str[spec->ie_id], spec->ie_id, htons(spec->length));
			}
			else {
				printf("[%04u] IE ID: %15s (id:%4u; length:%4u)\n", i, "[UNKNOWN]", spec->ie_id, htons(spec->length));
			}
		}

		/* Store it */
		if (template_count < template_max) {
			tmpl = templates + template_count;
			tmpl->type = htons(record->id);
			tmpl->length = data_flowset_len;
			template_count++;

			printf("[TMPL] Stored: Template ID:%u len:%u\n", htons(record->id), data_flowset_len);
		}
		
		printf("[Done] Template ID: %u (%u/%u)\n", htons(record->id), idx, flowset_length);
	}

	free(buffer);
	return idx;
}



int parse_set(gzFile file)
{
	struct ipfix_set_header header;
	int    len = sizeof(struct ipfix_set_header);
	if (gzread(file, &header, len) != len) {
		handle_bad_fread(file);
	}

	if (debug) {
		print_hex(&header, 0, sizeof(struct ipfix_set_header));
	}

	int rc;
	int set_id = htons(header.set_id);
	switch (set_id) {
	/* ID 0 is a flow template set */
	case 0: {
		printf("[TMPL] Set id: %u; Len: %u bytes\n", htons(header.set_id), htons(header.length));
		rc  = parse_template_set(file, htons(header.length));
		int len = (signed)htons(header.length) - sizeof(struct ipfix_set_header);
		if (rc != len) {
			printf("[WARN] read the wrong length: %u != %u\n", rc, htons(header.length));
		}
		break;
	}
	/* ID 1 is an options template set */
	case 1: {
		printf("[OPTS] Set id: %u; Len: %u bytes\n", htons(header.set_id), htons(header.length));
		rc = parse_options_template_set(file, htons(header.length));
		if (rc != htons(header.length)) {
			printf("[WARN] read the wrong length: %u != %u\n", rc, htons(header.length));
		}
		break;
	}
	/* ID > 255 is a flow set */
	/* ID < 256 && ID > 2 is pretty likely to be an error */
	default: {
		printf("[FLOW] Set id: %u; Len: %u bytes\n", htons(header.set_id), htons(header.length));
		if (set_id > 2 && set_id < 256) {
			gzseek(file, 0-len, SEEK_CUR);
			printf("[WARN] Unexpected set ID %u before full record count\n", set_id);
			return 0;
		}

		rc = parse_flow_set(file, set_id, htons(header.length));
	}
	}

	return rc;
}

int main(int argc, char *argv[])
{
	gzFile file;
	debug = false;

	int opt;
	while ((opt = getopt(argc, argv, "df:h")) != -1) {
		switch (opt) {
		case 'd': {
			debug = true;
			fprintf(stderr, "Enabled debug\n");
			break;
		}
		case 'f': {
			file = gzopen(optarg, "r");
			if (file == NULL) {
				fprintf(stderr, "Could not open file; error: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		}
		default:
		case 'h': {
			print_help(argv[0]);
			exit(EXIT_FAILURE);
		}
		}
	}

	templates = (struct template *)calloc(1, sizeof(struct template) * template_count);

	while (1) {
		int rc;
		int bootstrap = 0;
		struct ipfix_header     header;

		while (bootstrap < 128) {
			memset(&header, 0, sizeof(struct ipfix_header));
			rc = gzread(file, &header, sizeof(struct ipfix_header));
			if (rc != sizeof(struct ipfix_header)) {
				handle_bad_fread(file);
			}

			if (htons(header.version) != 9) {
				gzseek(file, 0-(sizeof(struct ipfix_header)-1), SEEK_CUR);
				bootstrap++;
			}
			else {
				break;
			}
		}
		if (bootstrap == 128) {
			printf("[.ERR] Failed to find NetFlow v9 header near start of file\n");
			exit(EXIT_FAILURE);
		}

		if (debug) {
			print_hex(&header, 0, sizeof(struct ipfix_header));
		}

		printf("\n");
		printf("[HEAD] Version: %x\n",      htons(header.version));
		printf("[HEAD] Record Count: %u\n", htons(header.rcount));
		printf("[HEAD] Uptime: %u\n",       htonl(header.uptime));
		printf("[HEAD] Export: %u\n",       htonl(header.export_ts));
		printf("[HEAD] Seq No: %u\n",       htonl(header.seq_no));
		printf("[HEAD] Src ID: %u\n",       htonl(header.obs_id));

		int record_count;
		//int bytes = sizeof(struct ipfix_header);
		for (record_count = 0; record_count < htons(header.rcount); ) {
			rc = parse_set(file);
			// hack hack hack: the flow_set will bail out if the set ID looks wrong
			// I've spotted this in probably-bad netflow dumps that list too many
			// records? hacking around it to understand the format.
			if (rc == 0) {
				if (record_count != htons(header.rcount)) {
					printf("[WARN] Bailed before number of headers was apparently read (%u != %u)\n",
						record_count, htons(header.rcount));
				}
				break;
			}
	
			record_count += rc;
		}
	}

	free(templates);

	return EXIT_SUCCESS;
}

