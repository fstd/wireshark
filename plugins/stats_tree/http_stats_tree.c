/* http_stats_tree.c
* Stats tree for HTTP
*
*  (c) 2005, Luis E. G. Ontanon <luis.ontanon@gmail.com>
*
* $Id$
*
* Ethereal - Network traffic analyzer
* By Gerald Combs <gerald@ethereal.com>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/stats_tree.h>
#include <epan/dissectors/packet-http.h>

static const value_string vals_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 199, "Informational - Others" },
		
	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 299, "Success - Others"},
		
	{ 300, "Multiple Choices"},
	{ 301, "Moved Permanently"},
	{ 302, "Moved Temporarily"},
	{ 303, "See Other"},
	{ 304, "Not Modified"},
	{ 305, "Use Proxy"},
	{ 399, "Redirection - Others"},
		
	{ 400, "Bad Request"},
	{ 401, "Unauthorized"},
	{ 402, "Payment Required"},
	{ 403, "Forbidden"},
	{ 404, "Not Found"},
	{ 405, "Method Not Allowed"},
	{ 406, "Not Acceptable"},
	{ 407, "Proxy Authentication Required"},
	{ 408, "Request Time-out"},
	{ 409, "Conflict"},
	{ 410, "Gone"},
	{ 411, "Length Required"},
	{ 412, "Precondition Failed"},
	{ 413, "Request Entity Too Large"},
	{ 414, "Request-URI Too Large"},
	{ 415, "Unsupported Media Type"},
	{ 499, "Client Error - Others"},
		
	{ 500, "Internal Server Error"},
	{ 501, "Not Implemented"},
	{ 502, "Bad Gateway"},
	{ 503, "Service Unavailable"},
	{ 504, "Gateway Time-out"},
	{ 505, "HTTP Version not supported"},
	{ 599, "Server Error - Others"},
		
	{ 0, 	NULL}
};


static const gchar* st_str_reqs = "HTTP Requests by Server";
static const gchar* st_str_reqs_by_srv_addr = "HTTP Requests by Server Address";
static const gchar* st_str_reqs_by_http_host = "HTTP Requests by HTTP Host";
static const gchar* st_str_resps_by_srv_addr = "HTTP Responses by Server Address";

static int st_node_reqs = -1;
static int st_node_reqs_by_srv_addr = -1;
static int st_node_reqs_by_http_host = -1;
static int st_node_resps_by_srv_addr = -1;

static void http_reqs_stats_tree_init(stats_tree* st) {
	st_node_reqs = stats_tree_create_node(st, st_str_reqs, 0, TRUE);
	st_node_reqs_by_srv_addr = stats_tree_create_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
	st_node_reqs_by_http_host = stats_tree_create_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
	st_node_resps_by_srv_addr = stats_tree_create_node(st, st_str_resps_by_srv_addr, 0, TRUE);
}

static int http_reqs_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
	int reqs_by_this_host;
	int reqs_by_this_addr;
	int resps_by_this_addr;
	int i = v->response_code;
	static gchar ip_str[256];
	
	
	if (v->request_method) {
		g_snprintf(ip_str,sizeof(ip_str),"%s",address_to_str(&pinfo->dst));

		tick_stat_node(st, st_str_reqs, 0, FALSE);
		tick_stat_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
		tick_stat_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
		reqs_by_this_addr = tick_stat_node(st, ip_str, st_node_reqs_by_srv_addr, TRUE);
		
		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_reqs_by_http_host, TRUE);
			tick_stat_node(st, ip_str, reqs_by_this_host, FALSE);
			
			tick_stat_node(st, v->http_host, reqs_by_this_addr, FALSE);
		}
		
		return 1;
		
	} else if (i != 0) {
		g_snprintf(ip_str,sizeof(ip_str),"%s",address_to_str(&pinfo->src));
		
		tick_stat_node(st, st_str_resps_by_srv_addr, 0, FALSE);
		resps_by_this_addr = tick_stat_node(st, ip_str, st_node_resps_by_srv_addr, TRUE);

		if ( (i>100)&&(i<400) ) {
			tick_stat_node(st, "OK", resps_by_this_addr, FALSE);
		} else {
			tick_stat_node(st, "KO", resps_by_this_addr, FALSE);
		}

		return 1;
	}
	
	return 0;
}


static int st_node_requests_by_host = -1;
static const guint8* st_str_requests_by_host = "HTTP Requests by HTTP Host";

static void http_req_stats_tree_init(stats_tree* st) {
	st_node_requests_by_host = stats_tree_create_node(st, st_str_requests_by_host, 0, TRUE);
}

static int http_req_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
	int reqs_by_this_host;
	
	if (v->request_method) {
		tick_stat_node(st, st_str_requests_by_host, 0, FALSE);
		
		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_requests_by_host, TRUE);
			
			if (v->request_uri) {
				tick_stat_node(st, v->request_uri, reqs_by_this_host, TRUE);
			}
		}
		
		return 1;
	}
	
	return 0;
}

static const guint8* st_str_packets = "Total HTTP Packets";
static const guint8* st_str_requests = "HTTP Request Packets";
static const guint8* st_str_responses = "HTTP Response Packets";
static const guint8* st_str_resp_broken = "???: broken";
static const guint8* st_str_resp_100 = "1xx: Informational";
static const guint8* st_str_resp_200 = "2xx: Success";
static const guint8* st_str_resp_300 = "3xx: Redirection";
static const guint8* st_str_resp_400 = "4xx: Client Error";
static const guint8* st_str_resp_500 = "5xx: Server Error";
static const guint8* st_str_other = "Other HTTP Packets";

static int st_node_packets = -1;
static int st_node_requests = -1;
static int st_node_responses = -1;
static int st_node_resp_broken = -1;
static int st_node_resp_100 = -1;
static int st_node_resp_200 = -1;
static int st_node_resp_300 = -1;
static int st_node_resp_400 = -1;
static int st_node_resp_500 = -1;
static int st_node_other = -1;


static void http_stats_tree_init(stats_tree* st) {
	st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);	
		st_node_requests = stats_tree_create_pivot_node(st, st_str_requests, st_node_packets);
		st_node_responses = stats_tree_create_node(st, st_str_responses, st_node_packets, TRUE);
			st_node_resp_broken = stats_tree_create_node(st, st_str_resp_broken, st_node_responses, TRUE);
			st_node_resp_100    = stats_tree_create_node(st, st_str_resp_100,    st_node_responses, TRUE);
			st_node_resp_200    = stats_tree_create_node(st, st_str_resp_200,    st_node_responses, TRUE);
			st_node_resp_300    = stats_tree_create_node(st, st_str_resp_300,    st_node_responses, TRUE);
			st_node_resp_400    = stats_tree_create_node(st, st_str_resp_400,    st_node_responses, TRUE);
			st_node_resp_500    = stats_tree_create_node(st, st_str_resp_500,    st_node_responses, TRUE);
		st_node_other = stats_tree_create_node(st, st_str_other, st_node_packets,FALSE);
}

static int http_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
	guint i = v->response_code;
	int resp_grp;
	const guint8* resp_str;
	static gchar str[64];
	
	tick_stat_node(st, st_str_packets, 0, FALSE);

	if (i) {
		tick_stat_node(st, st_str_responses, st_node_packets, FALSE);

		if ( (i<100)||(i>=600) ) {
			resp_grp = st_node_resp_broken;
			resp_str = st_str_resp_broken;
		} else if (i<200) {
			resp_grp = st_node_resp_100;
			resp_str = st_str_resp_100;
		} else if (i<300) {
			resp_grp = st_node_resp_200;
			resp_str = st_str_resp_200;
		} else if (i<400) {
			resp_grp = st_node_resp_300;
			resp_str = st_str_resp_300;
		} else if (i<500) {
			resp_grp = st_node_resp_400;
			resp_str = st_str_resp_400;
		} else {
			resp_grp = st_node_resp_500;
			resp_str = st_str_resp_500;
		}
		
		tick_stat_node(st, resp_str, st_node_responses, FALSE);

		g_snprintf(str, sizeof(str),"%u %s",i,match_strval(i,vals_status_code));
		tick_stat_node(st, str, resp_grp, FALSE);
	} else if (v->request_method) {
		stats_tree_tick_pivot(st,st_node_requests,v->request_method);
	} else {
		tick_stat_node(st, st_str_other, st_node_packets, FALSE);		
	}
	
	return 1;
}

/* register all http trees */
extern void register_http_stat_trees(void) {
	stats_tree_register("http","http","HTTP/Packet Tree", http_stats_tree_packet, http_stats_tree_init, NULL );
	stats_tree_register("http","http_req","HTTP/Request Tree", http_req_stats_tree_packet, http_req_stats_tree_init, NULL );
	stats_tree_register("http","http_srv","HTTP/Server Tree",http_reqs_stats_tree_packet,http_reqs_stats_tree_init, NULL );
}

