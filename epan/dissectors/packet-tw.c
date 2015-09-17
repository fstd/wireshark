#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tw_hm.h"

/* protocol flags (TODO: need strings) */
#define PKG_FLG_CTL 1
#define PKG_FLG_CONNLESS 2
#define PKG_FLG_RESEND 4
#define PKG_FLG_COMPRESS 8

#define NC_FLG_VITAL 1

/* (weak) limits */
#define PKG_MAXSZ 1400
#define MAX_MSGID 32 /* !! keep this a power of two, always */

/* netmsg magic numbers */
#define MSG_SYS_S_MAP_CHANGE 2
#define MSG_SYS_S_MAP_DATA 3
#define MSG_SYS_S_CON_READY 4
#define MSG_SYS_S_SNAP 5
#define MSG_SYS_S_SNAPEMPTY 6
#define MSG_SYS_S_SNAPSINGLE 7
#define MSG_SYS_S_INPUTTIMING 9
#define MSG_SYS_S_RCON_AUTH_STATUS 10
#define MSG_SYS_S_RCON_LINE 11
#define MSG_SYS_S_PING 22
#define MSG_SYS_S_PING_REPLY 23
#define MSG_SYS_S_SNAPSMALL 8
#define MSG_SYS_S_AUTH_CHALLANGE 12
#define MSG_SYS_S_AUTH_RESULT 13
#define MSG_SYS_C_INFO 1 
#define MSG_SYS_C_READY 14
#define MSG_SYS_C_ENTERGAME 15
#define MSG_SYS_C_INPUT 16
#define MSG_SYS_C_RCON_CMD 17
#define MSG_SYS_C_RCON_AUTH 18
#define MSG_SYS_C_REQUEST_MAP_DATA 19
#define MSG_SYS_C_AUTH_START 20 
#define MSG_SYS_C_AUTH_RESPONSE 21
#define MSG_SYS_B_PING 22
#define MSG_SYS_B_PING_REPLY 23
#define MSG_SYS_B_ERROR 24
#define MSG_USR_S_MOTD 1
#define MSG_USR_S_BROADCAST 2
#define MSG_USR_S_CHAT 3
#define MSG_USR_S_KILLMSG 4
#define MSG_USR_S_SOUNDGLOBAL 5
#define MSG_USR_S_TUNEPARAMS 6
#define MSG_USR_S_EXTRAPROJECTILE 7
#define MSG_USR_S_READYTOENTER 8
#define MSG_USR_S_WEAPONPICKUP 9
#define MSG_USR_S_EMOTICON 10
#define MSG_USR_S_VOTECLEAROPTIONS 11
#define MSG_USR_S_VOTEOPTIONLISTADD 12
#define MSG_USR_S_VOTEOPTIONADD 13
#define MSG_USR_S_VOTEOPTIONREMOVE 14
#define MSG_USR_S_VOTESET 15
#define MSG_USR_S_VOTESTATUS 16
#define MSG_USR_C_SAY 17
#define MSG_USR_C_SETTEAM 18
#define MSG_USR_C_SETSPECTATORMODE 19
#define MSG_USR_C_STARTINFO 20
#define MSG_USR_C_CHANGEINFO 21
#define MSG_USR_C_KILL 22
#define MSG_USR_C_EMOTICON 23
#define MSG_USR_C_VOTE 24
#define MSG_USR_C_CALLVOTE 25


/* reduce PITA while coding */
#define D(F, A...) fprintf(stderr, "%d:%s(): " F "\n", __LINE__, __func__, ##A)
#define PTAuint proto_tree_add_uint
#define PTAitem proto_tree_add_item
#define PTAtext proto_tree_add_text
#define PIAstree proto_item_add_subtree


static int proto_tw = -1;

/* header fields */
/* packet construct */
static int hf_pkg_flg = -1;
static int hf_pkg_ack = -1;
static int hf_pkg_nch = -1;

/* netchunk header */
static int hf_nc_flg = -1;
static int hf_nc_len = -1;
static int hf_nc_seq = -1;
static int hf_nc_sys = -1;
static int hf_nc_msg_s = -1;
static int hf_nc_msg_u = -1;

static int hf_sms_MAP_CHANGE_map = -1;
static int hf_sms_MAP_CHANGE_crc = -1;
static int hf_sms_MAP_CHANGE_sz = -1;

static int hf_sms_MAP_DATA_last = -1;
static int hf_sms_MAP_DATA_crc = -1;
static int hf_sms_MAP_DATA_chunk = -1;
static int hf_sms_MAP_DATA_chunksz = -1;
static int hf_sms_MAP_DATA_chunkdata = -1;

static int hf_smc_INFO_ver = -1;
static int hf_smc_INFO_pass = -1;

static int hf_ums_BROADCAST_msg = -1;

static int hf_umc_STARTINFO_name = -1;
static int hf_umc_STARTINFO_clan = -1;
static int hf_umc_STARTINFO_country = -1;
static int hf_umc_STARTINFO_skin = -1;
static int hf_umc_STARTINFO_custcol = -1;
static int hf_umc_STARTINFO_colbody = -1;
static int hf_umc_STARTINFO_colfeet = -1;

static int hf_umc_CHANGEINFO_name = -1;
static int hf_umc_CHANGEINFO_clan = -1;
static int hf_umc_CHANGEINFO_country = -1;
static int hf_umc_CHANGEINFO_skin = -1;
static int hf_umc_CHANGEINFO_custcol = -1;
static int hf_umc_CHANGEINFO_colbody = -1;
static int hf_umc_CHANGEINFO_colfeet = -1;

static int hf_smc_INPUT_acktick = -1;
static int hf_smc_INPUT_predtick = -1;
static int hf_smc_INPUT_inputsz = -1;
static int hf_smc_INPUT_inpelem = -1;
static int hf_ums_MOTD_motd = -1;
static int hf_ums_CHAT_team = -1;
static int hf_ums_CHAT_cid = -1;
static int hf_ums_CHAT_msg = -1;

static int hf_sms_INPUTTIMING_intdtick = -1;
static int hf_sms_INPUTTIMING_timeleft = -1;
	
/* subtrees */
static gint ett_tw = -1;
static gint ett_chunk = -1;
static gint ett_chunk_pl = -1;

/* prefs */
static guint pref_port = 8303;

/* subdissector dispatch */
typedef int (*fp_ds_msg)(tvbuff_t*, int, int, packet_info*, proto_tree*);
static fp_ds_msg ds_msg[2][MAX_MSGID];

static const value_string hf_nc_sys_strings[] = {
	{ 0, "User message" },
	{ 1, "System message" },
	{ 2, NULL }
};

static const value_string hf_nc_msg_s_strings[] = {
	{ 1, "SC_INFO" },
	{ 2, "SV_MAP_CHANGE" },
	{ 3, "SV_MAP_DATA" },
	{ 4, "SV_CON_READY" },
	{ 5, "SV_SNAP" },
	{ 6, "SV_SNAP_EMPTY" },
	{ 7, "SV_SNAP_SINGLE" },
	{ 8, "SV_SNAP_SMALL" },
	{ 9, "SV_INPUT_TIMING" },
	{ 10, "SV_RCON_AUTH_STATUS" },
	{ 11, "SV_RCON_LINE" },
	{ 12, "U_AUTH_CHALLENGE" },
	{ 13, "U_AUTH_RESULT" },
	{ 14, "CL_READY" },
	{ 15, "CL_ENTER_GAME" },
	{ 16, "CL_INPUT" },
	{ 17, "CL_RCON_CMD" },
	{ 18, "CL_RCON_AUTH" },
	{ 19, "CL_REQUEST_MAP_DATA" },
	{ 20, "U_AUTH_START" },
	{ 21, "U_AUTH_RESPONSE" },
	{ 22, "SC_PING" },
	{ 23, "SC_PING_REPLY" },
	{ 24, "SC_ERROR" },
	{ 0, NULL }
};
static const value_string hf_nc_msg_u_strings[] = {
	{ 1,  "SV_MOTD" },
	{ 2,  "SV_BROADCAST" },
	{ 3,  "SV_CHAT" },
	{ 4,  "SV_KILLMSG" },
	{ 5,  "SV_SOUNDGLOBAL" },
	{ 6,  "SV_TUNEPARAMS" },
	{ 7,  "SV_EXTRAPROJECTILE" },
	{ 8,  "SV_READYTOENTER" },
	{ 9,  "SV_WEAPONPICKUP" },
	{ 10,  "SV_EMOTICON" },
	{ 11, "SV_VOTECLEAROPTIONS" },
	{ 12, "SV_VOTEOPTIONLISTADD" },
	{ 13, "SV_VOTEOPTIONADD" },
	{ 14, "SV_VOTEOPTIONREMOVE" },
	{ 15, "SV_VOTESET" },
	{ 16, "SV_VOTESTATUS" },
	{ 17, "CL_SAY" },
	{ 18, "CL_SETTEAM" },
	{ 19, "CL_SETSPECTATORMODE" },
	{ 20, "CL_STARTINFO" },
	{ 21, "CL_CHANGEINFO" },
	{ 22, "CL_KILL" },
	{ 23, "CL_EMOTICON" },
	{ 24, "CL_VOTE" },
	{ 25, "CL_CALLVOTE" },
	{ 0, NULL }
};

/* top level dissector */
static int ds_tw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* packet type specific subdissectors */
static int ds_pkg_cf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                                       int nch);
static int ds_pkg_cl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int ds_pkg_ctl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int ds_dummy(tvbuff_t *tvb, int off, int len,
                                          packet_info *pinfo, proto_tree *tree);

/* helpers */
static int unpack_int(tvbuff_t *tvb, int off, int *pInOut);
static int extract_pkghead(tvbuff_t *tvb, unsigned *flags, int *ack, int *nch);
static int extract_nchead(tvbuff_t *tvb, int off,
                                        unsigned *cflags, int *clen, int *cseq);

/* handoff */
void proto_reg_handoff_tw(void);



/*============================================================================*/
/* dissection (top level) */
static int
ds_tw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int hlen, len, off = 0;
	unsigned pkg_flg;
	int pkg_ack, pkg_nch;
	proto_tree *tw_tree = NULL;
	proto_item *ti;
	tvbuff_t *next_tvb;

	len = tvb_captured_length(tvb);
	col_clear(pinfo->cinfo, COL_INFO);

	hlen = extract_pkghead(tvb, &pkg_flg, &pkg_ack, &pkg_nch);
	if ((pkg_flg & PKG_FLG_CONNLESS) == 0)
		off += hlen;

	if (tree)
	{
		ti = PTAitem(tree, proto_tw, tvb, 0, -1, ENC_NA);
		tw_tree = PIAstree(ti, ett_tw);
		/* connless packages have no meaningful pkgheader 
		 * (actually not even flags, however, this holds) */
		if ((pkg_flg & PKG_FLG_CONNLESS) == 0)
		{
			PTAuint(tw_tree, hf_pkg_flg, tvb, 0, 1, pkg_flg);
			PTAuint(tw_tree, hf_pkg_ack, tvb, 0, 2, pkg_ack);
			PTAuint(tw_tree, hf_pkg_nch, tvb, 2, 1, pkg_nch);
		}

		if ((pkg_flg & PKG_FLG_CONNLESS) == 0
		                                && (pkg_flg & PKG_FLG_COMPRESS))
		{
			static guint8 uncompr[2500];//XXX
			int res;
			res = tw_hm_decompr(tvb_get_ptr(tvb, off, -1),
			                         tvb_length_remaining(tvb, off),
			                         uncompr, sizeof uncompr);

			if (res < 0)
			{
				D("mr huffman failed :O\n");
				return off;//XXX
			}

			next_tvb = tvb_new_real_data(uncompr, res, res);
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);
			add_new_data_source(pinfo, next_tvb,
			                                "Decompressed Payload");
		}
		else
			next_tvb = tvb_new_subset(tvb, off, -1, -1);

		off = 0;
	}
	else
		next_tvb = tvb;


	if (pkg_flg & PKG_FLG_CONNLESS)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "TW Connless Packet"); 
		return tree ? ds_pkg_cl(next_tvb, pinfo, tw_tree)
		            : (int)tvb_captured_length(next_tvb);
	}
	else if (pkg_flg & PKG_FLG_CTL)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "TW Control Packet"); 
		return tree ? ds_pkg_ctl(next_tvb, pinfo, tw_tree)
		            : (int)tvb_captured_length(next_tvb);
	}
	col_add_fstr(pinfo->cinfo, COL_INFO, "TW Regular Packet (%s%s)", 
	                 (pkg_flg&PKG_FLG_COMPRESS)?"compressed":"uncompressed",
	                 (pkg_flg&PKG_FLG_RESEND)?", resent":"");

	return tree ? ds_pkg_cf(next_tvb, pinfo, tw_tree, pkg_nch)
	            : (int)tvb_captured_length(next_tvb);
}

/* dissection (regular packets) */
static int
ds_pkg_cf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int nch)
{
	proto_tree *nc_tree = NULL;
	proto_tree *chpl_tree = NULL;
	proto_item *ti;
	gchar colinfo[128];

	int i;
	int off = 0;
	(void)pinfo;
	colinfo[0] = '('; colinfo[1] = '\0';
	for(i = 0; i < nch; i++)
	{
		unsigned cflags;
		int clen, cseq;
		int msys, mmsg;
		int hlen;
		hlen = extract_nchead(tvb, off, &cflags, &clen, &cseq);

		ti = PTAtext(tree, tvb, off, hlen + clen, "Chunk #%d", i + 1);
		nc_tree = PIAstree(ti, ett_chunk);
		PTAuint(nc_tree, hf_nc_flg, tvb, off, 1, cflags);
		PTAuint(nc_tree, hf_nc_len, tvb, off, 2, clen);
		if (cflags&NC_FLG_VITAL)
			PTAuint(nc_tree, hf_nc_seq, tvb, off+1, 2, cseq);
		off += hlen;

		hlen = unpack_int(tvb, off, &mmsg);

		msys = mmsg&1;
		mmsg = ((unsigned)mmsg) >> 1;

		/* make info a bit more precise 
		 * XXX HACK: how properly access value strings for hfs? */
		{
		int len = strlen(colinfo);
		int rem = (sizeof colinfo) - len - 1;
		if (rem > 0)
			g_snprintf(colinfo + len, rem, "%s%c/%s", i?", ":"",
		                   msys ? 'S' : 'U', 
			           msys ? (hf_nc_msg_s_strings[mmsg-1].strptr)
		                        : (hf_nc_msg_u_strings[mmsg-1].strptr));

		}
		PTAuint(nc_tree, hf_nc_sys, tvb, off, 1, msys);
		if (msys)
			PTAuint(nc_tree, hf_nc_msg_s, tvb, off, hlen, mmsg);
		else
			PTAuint(nc_tree, hf_nc_msg_u, tvb, off, hlen, mmsg);

		if (ds_msg[msys][mmsg&(MAX_MSGID-1)])
		{
			ti = PTAtext(nc_tree, tvb, off + hlen, clen - hlen,
			             "Message payload (%d bytes)", clen - hlen);
			chpl_tree = PIAstree(ti, ett_chunk_pl);
			ds_msg[msys][mmsg&(MAX_MSGID-1)](tvb, off + hlen,
			                         clen - hlen, pinfo, chpl_tree);
		}
		else
			ds_dummy(tvb, off, clen, pinfo, nc_tree);

		off += clen;
	}
	
	col_add_fstr(pinfo->cinfo, COL_INFO, "TW Packet, %d chunks %s)",
	                                                          nch, colinfo); 

	return off;
}

#define GETSTRING(VAR, HF) do{\
  VAR = (gchar*)tvb_get_const_stringz(tvb, off, &VAR ## _len); \
  proto_tree_add_string(tree, HF, tvb, off, VAR ## _len, VAR); \
  off += VAR ## _len;}while(0)

#define GETINT(VAR, HF) do{\
  int _hlen = unpack_int(tvb, off, &VAR); \
  PTAuint(tree, HF, tvb, off, _hlen, VAR); \
  off += _hlen;}while(0)


static int ds_dummy(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	int hlen;
	int mmsg, msys;
	hlen = unpack_int(tvb, off, &mmsg);

	off += hlen; len -= hlen;

	msys = mmsg&1;
	mmsg = ((unsigned)mmsg) >> 1;

	PTAtext(tree, tvb, off, len, "Payload (%d B) of unknown msg %d/%d",
	                                                       len, msys, mmsg);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len + hlen;
}

static int ds_sms_MAP_CHANGE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	int hlen;
	guint32 crc, sz;
	int ooff;
	gint map_len;
	gchar *map;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;
	map = (gchar*)tvb_get_const_stringz(tvb, off, &map_len);

	proto_tree_add_string(tree, hf_sms_MAP_CHANGE_map, tvb, off, map_len, map);
	off += map_len;

	hlen = unpack_int(tvb, off, &crc);

	PTAuint(tree, hf_sms_MAP_CHANGE_crc, tvb, off, hlen, crc);
	off += hlen;

	hlen = unpack_int(tvb, off, &sz);
	PTAuint(tree, hf_sms_MAP_CHANGE_sz, tvb, off, hlen, sz);
	off += hlen;

	(void)pinfo;
	return off - ooff;
}

static int ds_sms_MAP_DATA(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	guint32 last, chunk, crc, chunksz;
	int hlen, rlen;
	int ooff;
	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	hlen = unpack_int(tvb, off, &last);

	PTAuint(tree, hf_sms_MAP_DATA_last, tvb, off, hlen, last);
	off += hlen;
	hlen = unpack_int(tvb, off, &crc);

	PTAuint(tree, hf_sms_MAP_DATA_crc, tvb, off, hlen, crc);
	off += hlen;
	hlen = unpack_int(tvb, off, &chunk);

	PTAuint(tree, hf_sms_MAP_DATA_chunk, tvb, off, hlen, chunk);
	off += hlen;
	hlen = unpack_int(tvb, off, &chunksz);

	PTAuint(tree, hf_sms_MAP_DATA_chunksz, tvb, off, hlen, chunksz);
	off += hlen;

	rlen = len - (off - ooff);
	proto_tree_add_bytes(tree, hf_sms_MAP_DATA_chunkdata, tvb, off, rlen,
	                                           tvb_get_ptr(tvb, off, rlen));

	(void)pinfo;
	return off - ooff;
}
/*
	gint32 someint
	gchar *somestr;
	gint somestr_len;
	int hlen;
	int ooff;
	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETINT(someint, hf_xmy_WHATEVER_someint);
	GETSTRING(somestr, hf_xmy_WHATEVER_somestr);

	(void)pinfo;
	return off - ooff;
*/

static int ds_sms_CON_READY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_SNAP(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_SNAPEMPTY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_SNAPSINGLE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_INPUTTIMING(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	gint32 intdtick, timeleft;
	int ooff;
	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETINT(intdtick, hf_sms_INPUTTIMING_intdtick);
	GETINT(timeleft, hf_sms_INPUTTIMING_timeleft);

	(void)pinfo;
	return off - ooff;
}

static int ds_sms_RCON_AUTH_STATUS(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_RCON_LINE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_PING(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_PING_REPLY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)off; (void)len; (void)pinfo; (void)tree;
	return len;
}

static int ds_sms_SNAPSMALL(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_sms_AUTH_CHALLANGE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_sms_AUTH_RESULT(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_INFO(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	int ooff;
	gint ver_len, pass_len;
	gchar *ver, *pass;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	ver = (gchar*)tvb_get_const_stringz(tvb, off, &ver_len);
	proto_tree_add_string(tree, hf_smc_INFO_ver, tvb, off, ver_len, ver);
	off += ver_len;

	pass = (gchar*)tvb_get_const_stringz(tvb, off, &pass_len);
	proto_tree_add_string(tree, hf_smc_INFO_pass, tvb, off, pass_len, pass);
	off += pass_len;

	(void)pinfo;
	return off - ooff;
}
static int ds_smc_READY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_ENTERGAME(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_INPUT(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	int i;


	guint32 acktick, predtick, sz;
	int ooff;
	guint32 elem;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETINT(acktick, hf_smc_INPUT_acktick);
	GETINT(predtick, hf_smc_INPUT_predtick);
	GETINT(sz, hf_smc_INPUT_inputsz);

	elem = sz>>2;

	if (elem == 10) /*we know this XXX sanitize */
	{
		int hlen;
		int  iel;
		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                           tvb, off, hlen, iel, "Direction: %s",
					   iel<0?"Left":iel>0?"Right":"None");
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                       tvb, off, hlen, iel, "TargetX: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                       tvb, off, hlen, iel, "TargetY: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                          tvb, off, hlen, iel, "Jump: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                          tvb, off, hlen, iel, "Fire: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                          tvb, off, hlen, iel, "Hook: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                  tvb, off, hlen, iel, "Player flags: %x", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                 tvb, off, hlen, iel, "Wanted weapon: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                   tvb, off, hlen, iel, "Next weapon: %d", iel);
		off += hlen;

		hlen = unpack_int(tvb, off, &iel);
		proto_tree_add_int_format_value(tree, hf_smc_INPUT_inpelem,
		                   tvb, off, hlen, iel, "Prev weapon: %d", iel);
		off += hlen;
	}
	else
	{
		for(i = 0; i < (int)elem; i++)
		{
			int inp;
			GETINT(inp, hf_smc_INPUT_inpelem);
		}
	}

	(void)pinfo;
	return off - ooff;
}
static int ds_smc_RCON_CMD(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_RCON_AUTH(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_REQUEST_MAP_DATA(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_AUTH_START(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smc_AUTH_RESPONSE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smb_PING(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smb_PING_REPLY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_smb_ERROR(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_MOTD(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	gint motd_len;
	int ooff;
	gchar *motd;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETSTRING(motd, hf_ums_MOTD_motd);

	(void)pinfo;
	return off - ooff;
}
static int ds_ums_BROADCAST(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	gchar *msg;
	gint msg_len;
	int ooff;
	D("subdissector called (off: %d, len: %d)", off, len);
	ooff = off;
	msg = (gchar*)tvb_get_const_stringz(tvb, off, &msg_len);
	proto_tree_add_string(tree, hf_ums_BROADCAST_msg, tvb, off, msg_len, msg);
	off += msg_len;
	(void)pinfo;
	return off - ooff;
}
static int ds_ums_CHAT(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	gchar *msg;
	gint msg_len;
	gint32 team, cid;
	int ooff;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETINT(team, hf_ums_CHAT_team);
	GETINT(cid, hf_ums_CHAT_cid);
	GETSTRING(msg, hf_ums_CHAT_msg);

	(void)pinfo;
	return off - ooff;
}
static int ds_ums_KILLMSG(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_SOUNDGLOBAL(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_TUNEPARAMS(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_EXTRAPROJECTILE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_READYTOENTER(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_WEAPONPICKUP(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_EMOTICON(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTECLEAROPTIONS(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTEOPTIONLISTADD(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTEOPTIONADD(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTEOPTIONREMOVE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTESET(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_ums_VOTESTATUS(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_SAY(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_SETTEAM(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_SETSPECTATORMODE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}

static int ds_umc_STARTINFO(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	guint32 country, custcol, colbody, colfeet;
	gint name_len, clan_len, skin_len;
	int ooff;
	gchar *name, *clan, *skin;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETSTRING(name, hf_umc_STARTINFO_name);
	GETSTRING(clan, hf_umc_STARTINFO_clan);
	GETINT(country, hf_umc_STARTINFO_country);
	GETSTRING(skin, hf_umc_STARTINFO_skin);
	GETINT(custcol, hf_umc_STARTINFO_custcol);
	GETINT(colbody, hf_umc_STARTINFO_colbody);
	GETINT(colfeet, hf_umc_STARTINFO_colfeet);

	(void)pinfo;
	return off - ooff;
}
static int ds_umc_CHANGEINFO(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	guint32 country, custcol, colbody, colfeet;
	gint name_len, clan_len, skin_len;
	int ooff;
	gchar *name, *clan, *skin;

	D("subdissector called (off: %d, len: %d)", off, len);

	ooff = off;

	GETSTRING(name, hf_umc_CHANGEINFO_name);
	GETSTRING(clan, hf_umc_CHANGEINFO_clan);
	GETINT(country, hf_umc_CHANGEINFO_country);
	GETSTRING(skin, hf_umc_CHANGEINFO_skin);
	GETINT(custcol, hf_umc_CHANGEINFO_custcol);
	GETINT(colbody, hf_umc_CHANGEINFO_colbody);
	GETINT(colfeet, hf_umc_CHANGEINFO_colfeet);

	(void)pinfo;
	return off - ooff;
}
static int ds_umc_KILL(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_EMOTICON(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_VOTE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
static int ds_umc_CALLVOTE(tvbuff_t *tvb, int off, int len,
                                           packet_info *pinfo, proto_tree *tree)
{
	D("subdissector called (off: %d, len: %d)", off, len);
	(void)tvb; (void)pinfo; (void)tree;
	return len;
}
/* dissection (connless packets) */
static int
ds_pkg_cl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{(void)pinfo;(void)tree;
	return tvb_captured_length(tvb);
}

/* dissection (ctl packets) */
static int
ds_pkg_ctl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{(void)pinfo;(void)tree;
	return tvb_captured_length(tvb);
}

/*return number of bytes the int took, relies on that there is actually enough*/
static int unpack_int(tvbuff_t *tvb, int off, int *pInOut)
{
	int Sign = (tvb_get_guint8(tvb, off)>>6)&1;
	int OrigOffset = off;
	*pInOut = tvb_get_guint8(tvb, off)&0x3F;

	do
	{
		if(!(tvb_get_guint8(tvb, off)&0x80)) break;
		off++;
		*pInOut |= (tvb_get_guint8(tvb, off)&(0x7F))<<(6);

		if(!(tvb_get_guint8(tvb, off)&0x80)) break;
		off++;
		*pInOut |= (tvb_get_guint8(tvb, off)&(0x7F))<<(6+7);

		if(!(tvb_get_guint8(tvb, off)&0x80)) break;
		off++;
		*pInOut |= (tvb_get_guint8(tvb, off)&(0x7F))<<(6+7+7);

		if(!(tvb_get_guint8(tvb, off)&0x80)) break;
		off++;
		*pInOut |= (tvb_get_guint8(tvb, off)&(0x7F))<<(6+7+7+7);
	} while(0);

	off++;
	*pInOut ^= -Sign; // if(sign) *i = ~(*i)
	return off - OrigOffset;
}

/* relies on arguments being not null */
static int
extract_pkghead(tvbuff_t *tvb, unsigned *flags, int *ack, int *nch)
{
	/* doing thorough check, first we must decompress, if compressed */
	guint8 head[3];
	int i = 0;
	for(; i < 3; i++)
		head[i] = tvb_get_guint8(tvb, i);
	
	*flags = (head[0]&0xf0)>>4;
	*ack = ((head[0]&0x0f)<<8) | head[1];
	*nch = head[2];

	return 3;
}

static int
extract_nchead(tvbuff_t *tvb, int off, unsigned *cflags, int *clen, int *cseq)
{
	guint8 head[3];
	int i = 0;
	for(; i < 2; i++)
		head[i] = tvb_get_guint8(tvb, off + i);

	*cflags = (head[0]>>6)&3;
	*clen = ((head[0]&0x3f)<<4) | (head[1]&0xf);
	*cseq = -1;
	if (*cflags & NC_FLG_VITAL)
	{
		head[2] = tvb_get_guint8(tvb, off + 2);
		*cseq = ((head[1]&0xf0)<<2) | head[2];
		return 3;
	}

	return 2;
}

/*------------------------- registration and handoff -------------------------*/
void
proto_register_tw(void)
{
	module_t *tw_module;

	static hf_register_info hf[] = {
		
		{ &hf_pkg_flg, {
		    "Packet construct flags",
		    "tw.pkg_flg",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Teeworlds Packet-construct flags", HFILL } },
		
		{ &hf_pkg_ack, {
		    "Pakcet ack#",
		    "tw.pkg_ack",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Teeworlds Packet-construct ack#", HFILL } },
		
		{ &hf_pkg_nch, {
		    "Number of chunks",
		    "tw.pkg_nch",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Teeworlds Packet-construct number of chunks", HFILL } },
		
		{ &hf_nc_flg, {
		    "Netchunk flags",
		    "tw.nc_flg",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "netchunk flags", HFILL } },

		{ &hf_nc_len, {
		    "Netchunk len",
		    "tw.nc_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "netchunk len", HFILL } },

		{ &hf_nc_seq, {
		    "Netchunk seq#",
		    "tw.nc_seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "netchunk seq", HFILL } },

		{ &hf_nc_sys, {
		    "Message Class",
		    "tw.msg_class",
		    FT_UINT8, BASE_DEC, VALS(hf_nc_sys_strings), 0x0,
		    "message class", HFILL } },

		{ &hf_nc_msg_s, {
		    "Message Type (Sys)",
		    "tw.msg_type_s",
		    FT_UINT8, BASE_DEC, VALS(hf_nc_msg_s_strings), 0x0,
		    "message type (sysmsgs)", HFILL } },

		{ &hf_nc_msg_u, {
		    "Message Type (Usr)",
		    "tw.msg_type_u",
		    FT_UINT8, BASE_DEC, VALS(hf_nc_msg_u_strings), 0x0,
		    "message type (usrmsgs)", HFILL } },

		{ &hf_sms_MAP_CHANGE_map, {
		    "hf_sms_MAP_CHANGE_map",
		    "tw.sms_MAP_CHANGE_map",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "sms_MAP_CHANGE_map", HFILL } },

		{ &hf_sms_MAP_CHANGE_crc, {
		    "hf_sms_MAP_CHANGE_crc",
		    "tw.sms_MAP_CHANGE_crc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "sms_MAP_CHANGE_crc", HFILL } },

		{ &hf_sms_MAP_CHANGE_sz, {
		    "hf_sms_MAP_CHANGE_sz",
		    "tw.sms_MAP_CHANGE_sz",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "sms_MAP_CHANGE_sz", HFILL } },

		{ &hf_sms_MAP_DATA_last, {
		    "hf_sms_MAP_DATA_last",
		    "tw._DATA_last",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "_DATA_last", HFILL } },

		{ &hf_sms_MAP_DATA_crc, {
		    "hf_sms_MAP_DATA_crc",
		    "tw._DATA_crc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "_DATA_crc", HFILL } },

		{ &hf_sms_MAP_DATA_chunk, {
		    "hf_sms_MAP_DATA_chunk",
		    "tw._DATA_chunk",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "_DATA_chunk", HFILL } },

		{ &hf_sms_MAP_DATA_chunksz, {
		    "hf_sms_MAP_DATA_chunksz",
		    "tw._DATA_chunksz",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "_DATA_chunksz", HFILL } },

		{ &hf_sms_MAP_DATA_chunkdata, {
		    "hf_sms_MAP_DATA_chunkdata",
		    "tw._DATA_chunkdata",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "_DATA_chunkdata", HFILL } },

		{ &hf_smc_INFO_ver, {
		    "hf_smc_INFO_ver",
		    "tw.INFO_ver",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "INFO_ver", HFILL } },

		{ &hf_smc_INFO_pass, {
		    "hf_smc_INFO_pass",
		    "tw.INFO_pass",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "INFO_pass", HFILL } },

		{ &hf_umc_CHANGEINFO_name, {
		    "hf_umc_CHANGEINFO_name",
		    "tw.CHANGEINFO_name",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "CHANGEINFO_name", HFILL } },

		{ &hf_umc_CHANGEINFO_clan, {
		    "hf_umc_CHANGEINFO_clan",
		    "tw.CHANGEINFO_clan",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "CHANGEINFO_clan", HFILL } },

		{ &hf_umc_CHANGEINFO_country, {
		    "hf_umc_CHANGEINFO_country",
		    "tw.CHANGEINFO_country",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "CHANGEINFO_country", HFILL } },

		{ &hf_umc_CHANGEINFO_skin, {
		    "hf_umc_CHANGEINFO_skin",
		    "tw.CHANGEINFO_skin",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "CHANGEINFO_skin", HFILL } },

		{ &hf_umc_CHANGEINFO_custcol, {
		    "hf_umc_CHANGEINFO_custcol",
		    "tw.CHANGEINFO_custcol",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "CHANGEINFO_custcol", HFILL } },

		{ &hf_umc_CHANGEINFO_colbody, {
		    "hf_umc_CHANGEINFO_colbody",
		    "tw.CHANGEINFO_colbody",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "CHANGEINFO_colbody", HFILL } },

		{ &hf_umc_CHANGEINFO_colfeet, {
		    "hf_umc_CHANGEINFO_colfeet",
		    "tw.CHANGEINFO_colfeet",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "CHANGEINFO_colfeet", HFILL } },

		{ &hf_umc_STARTINFO_name, {
		    "hf_umc_STARTINFO_name",
		    "tw.STARTINFO_name",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "STARTINFO_name", HFILL } },

		{ &hf_umc_STARTINFO_clan, {
		    "hf_umc_STARTINFO_clan",
		    "tw.STARTINFO_clan",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "STARTINFO_clan", HFILL } },

		{ &hf_umc_STARTINFO_country, {
		    "hf_umc_STARTINFO_country",
		    "tw.STARTINFO_country",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "STARTINFO_country", HFILL } },

		{ &hf_umc_STARTINFO_skin, {
		    "hf_umc_STARTINFO_skin",
		    "tw.STARTINFO_skin",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "STARTINFO_skin", HFILL } },

		{ &hf_umc_STARTINFO_custcol, {
		    "hf_umc_STARTINFO_custcol",
		    "tw.STARTINFO_custcol",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "STARTINFO_custcol", HFILL } },

		{ &hf_umc_STARTINFO_colbody, {
		    "hf_umc_STARTINFO_colbody",
		    "tw.STARTINFO_colbody",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "STARTINFO_colbody", HFILL } },

		{ &hf_umc_STARTINFO_colfeet, {
		    "hf_umc_STARTINFO_colfeet",
		    "tw.STARTINFO_colfeet",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "STARTINFO_colfeet", HFILL } },

		{ &hf_ums_BROADCAST_msg, {
		    "hf_ums_BROADCAST_msg",
		    "tw.BROADCAST_msg",
		    FT_STRINGZ, BASE_NONE , NULL, 0x0,
		    "BROADCAST_msg", HFILL } }, 

		{ &hf_smc_INPUT_acktick, {
		    "hf_smc_INPUT_acktick",
		    "tw.INPUT_acktick",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "INPUT_acktick", HFILL } },

		{ &hf_smc_INPUT_predtick, {
		    "hf_smc_INPUT_predtick",
		    "tw.INPUT_predtick",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "INPUT_predtick", HFILL } },

		{ &hf_smc_INPUT_inputsz, {
		    "hf_smc_INPUT_inputsz",
		    "tw.INPUT_inputsz",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "INPUT_inputsz", HFILL } },

		{ &hf_smc_INPUT_inpelem, {
		    "hf_smc_INPUT_inpelem",
		    "tw.INPUT_inpelem",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "INPUT_inpelem", HFILL } },

		{ &hf_ums_MOTD_motd, {
		    "hf_ums_MOTD_motd",
		    "tw.MOTD_motd",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "MOTD_motd", HFILL } },

		{ &hf_ums_CHAT_team, {
		    "hf_ums_CHAT_team",
		    "tw.CHAT_team",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "CHAT_team", HFILL } },

		{ &hf_ums_CHAT_cid, {
		    "hf_ums_CHAT_cid",
		    "tw.CHAT_cid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "CHAT_cid", HFILL } },

		{ &hf_ums_CHAT_msg, {
		    "hf_ums_CHAT_msg",
		    "tw.CHAT_msg",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "CHAT_msg", HFILL } },

		{ &hf_sms_INPUTTIMING_intdtick, {
		    "hf_sms_INPUTTIMING_intdtick",
		    "tw.INPUTTIMING_intdtick",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "INPUTTIMING_intdtick", HFILL } },

		{ &hf_sms_INPUTTIMING_timeleft, {
		    "hf_sms_INPUTTIMING_timeleft",
		    "tw.INPUTTIMING_timeleft",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "INPUTTIMING_timeleft", HFILL } }
	};

	static gint *ett[] = {
		&ett_tw,
		&ett_chunk,
		&ett_chunk_pl
	};

	proto_tw = proto_register_protocol("Teeworlds", "TW", "tw");

	proto_register_field_array(proto_tw, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tw_module = prefs_register_protocol(proto_tw, proto_reg_handoff_tw);

	prefs_register_uint_preference(tw_module, "udp.port", "tw UDP Port",
	              " tw UDP port if other than the default", 10, &pref_port);

	/* haha disregard this, i suck cocks */
	#define REG(SYS,TYPE,NAME) ds_msg[SYS][TYPE] = ds_sms_##NAME;
	REG(1, MSG_SYS_S_MAP_CHANGE, MAP_CHANGE);
	REG(1, MSG_SYS_S_MAP_DATA, MAP_DATA);
	REG(1, MSG_SYS_S_CON_READY, CON_READY);
	REG(1, MSG_SYS_S_SNAP, SNAP);
	REG(1, MSG_SYS_S_SNAPEMPTY, SNAPEMPTY);
	REG(1, MSG_SYS_S_SNAPSINGLE, SNAPSINGLE);
	REG(1, MSG_SYS_S_INPUTTIMING, INPUTTIMING);
	REG(1, MSG_SYS_S_RCON_AUTH_STATUS, RCON_AUTH_STATUS);
	REG(1, MSG_SYS_S_RCON_LINE, RCON_LINE);
	REG(1, MSG_SYS_S_PING, PING);
	REG(1, MSG_SYS_S_PING_REPLY, PING_REPLY);
	REG(1, MSG_SYS_S_SNAPSMALL, SNAPSMALL);
	REG(1, MSG_SYS_S_AUTH_CHALLANGE, AUTH_CHALLANGE);
	REG(1, MSG_SYS_S_AUTH_RESULT, AUTH_RESULT);
	#undef REG
	#define REG(SYS,TYPE,NAME) ds_msg[SYS][TYPE] = ds_smc_##NAME;
	REG(1, MSG_SYS_C_INFO, INFO);
	REG(1, MSG_SYS_C_READY, READY);
	REG(1, MSG_SYS_C_ENTERGAME, ENTERGAME);
	REG(1, MSG_SYS_C_INPUT, INPUT);
	REG(1, MSG_SYS_C_RCON_CMD, RCON_CMD);
	REG(1, MSG_SYS_C_RCON_AUTH, RCON_AUTH);
	REG(1, MSG_SYS_C_REQUEST_MAP_DATA, REQUEST_MAP_DATA);
	REG(1, MSG_SYS_C_AUTH_START, AUTH_START);
	REG(1, MSG_SYS_C_AUTH_RESPONSE, AUTH_RESPONSE);
	#undef REG
	#define REG(SYS,TYPE,NAME) ds_msg[SYS][TYPE] = ds_smb_##NAME;
	REG(1, MSG_SYS_B_PING, PING);
	REG(1, MSG_SYS_B_PING_REPLY, PING_REPLY);
	REG(1, MSG_SYS_B_ERROR, ERROR);
	#undef REG
	#define REG(SYS,TYPE,NAME) ds_msg[SYS][TYPE] = ds_ums_##NAME;
	REG(0, MSG_USR_S_MOTD, MOTD);
	REG(0, MSG_USR_S_BROADCAST, BROADCAST);
	REG(0, MSG_USR_S_CHAT, CHAT);
	REG(0, MSG_USR_S_KILLMSG, KILLMSG);
	REG(0, MSG_USR_S_SOUNDGLOBAL, SOUNDGLOBAL);
	REG(0, MSG_USR_S_TUNEPARAMS, TUNEPARAMS);
	REG(0, MSG_USR_S_EXTRAPROJECTILE, EXTRAPROJECTILE);
	REG(0, MSG_USR_S_READYTOENTER, READYTOENTER);
	REG(0, MSG_USR_S_WEAPONPICKUP, WEAPONPICKUP);
	REG(0, MSG_USR_S_EMOTICON, EMOTICON);
	REG(0, MSG_USR_S_VOTECLEAROPTIONS, VOTECLEAROPTIONS);
	REG(0, MSG_USR_S_VOTEOPTIONLISTADD, VOTEOPTIONLISTADD);
	REG(0, MSG_USR_S_VOTEOPTIONADD, VOTEOPTIONADD);
	REG(0, MSG_USR_S_VOTEOPTIONREMOVE, VOTEOPTIONREMOVE);
	REG(0, MSG_USR_S_VOTESET, VOTESET);
	REG(0, MSG_USR_S_VOTESTATUS, VOTESTATUS);
	#undef REG
	#define REG(SYS,TYPE,NAME) ds_msg[SYS][TYPE] = ds_umc_##NAME;
	REG(0, MSG_USR_C_SAY, SAY);
	REG(0, MSG_USR_C_SETTEAM, SETTEAM);
	REG(0, MSG_USR_C_SETSPECTATORMODE, SETSPECTATORMODE);
	REG(0, MSG_USR_C_STARTINFO, STARTINFO);
	REG(0, MSG_USR_C_CHANGEINFO, CHANGEINFO);
	REG(0, MSG_USR_C_KILL, KILL);
	REG(0, MSG_USR_C_EMOTICON, EMOTICON);
	REG(0, MSG_USR_C_VOTE, VOTE);
	REG(0, MSG_USR_C_CALLVOTE, CALLVOTE);
	#undef REG
}


void
proto_reg_handoff_tw(void)
{
	dissector_handle_t tw_handle;

	tw_handle = new_create_dissector_handle(ds_tw, proto_tw);
	dissector_add_uint("udp.port", 8303, tw_handle);
}
