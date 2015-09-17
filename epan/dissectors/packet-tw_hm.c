#ifdef HAVE_CONFIG_H /*required here?*/
# include "config.h" /*or even this?*/
#endif

/*------------------------- (1.2) stdlib -------------------------------------*/
#include <string.h>

#include "packet-tw_hm.h"

#define HUFFMAN_EOF_SYMBOL 256
#define HUFFMAN_MAX_SYMBOLS (HUFFMAN_EOF_SYMBOL+1)
#define HUFFMAN_MAX_NODES ((HUFFMAN_MAX_SYMBOLS)*2-1)
#define HUFFMAN_LUTBITS 10
#define HUFFMAN_LUTSIZE (1<<HUFFMAN_LUTBITS)
#define HUFFMAN_LUTMASK ((HUFFMAN_LUTSIZE)-1)

struct huffman_node
{
	unsigned bits;
	unsigned num_bits;
	unsigned short leafs[2];
	unsigned char symbol;
};

struct huffman_cnode
{
	unsigned short node_id;
	int freq;
}; 

struct huffman
{
	struct huffman_node nodes[HUFFMAN_MAX_NODES];
	struct huffman_node *decode_lut[HUFFMAN_LUTSIZE];
	struct huffman_node *start_node;
	int num_nodes;
};

static struct huffman hm;
static int hm_initialized = 0;

static const unsigned hm_freqtbl[256+1] = {
	1<<30,4545,2657,431,1950,919,444,482,2244,617,838,542,715,1814,304,240,
	  754, 212, 647,186, 283,131,146,166, 543,164,167,136,179, 859,363,113,
	  157, 154, 204,108, 137,180,202,176, 872,404,168,134,151, 111,113,109,
	  120, 126, 129,100,  41, 20, 16, 22,  18, 18, 17, 19, 16,  37, 13,21,
	  362, 166,  99, 78,  95, 88, 81, 70,  83,284, 91,187, 77,  68, 52,68,
	   59,  66,  61,638,  71,157, 50, 46,  69, 43, 11, 24, 13,  19, 10,12,
	   12,  20,  14,  9,  20, 20, 10, 10,  15, 15, 12, 12,  7,  19, 15,14,
	   13,  18,  35, 19,  17, 14,  8,  5,  15, 17,  9, 15, 14,  18,  8,10,
	 2173, 134, 157, 68, 188, 60,170, 60, 194, 62,175, 71,148,  67,167,78,
	  211,  67, 156, 69,1674, 90,174, 53, 147, 89,181, 51,174,  63,163,80,
	  167,  94, 128,122, 223,153,218, 77, 200,110,190, 73,174,  69,145,66,
	  277, 143, 141, 60, 136, 53,180, 57, 142, 57,158, 61,166, 112,152,92,
	   26,  22,  21, 28,  20, 26, 30, 21,  32, 27, 20, 17, 23,  21, 30,22,
	   22,  21,  27, 25,  17, 27, 23, 18,  39, 26, 15, 21, 12,  18, 18,27,
	   20,  18,  15, 19,  11, 17, 33, 12,  18, 15, 19, 18, 16,  26, 17,18,
	    9,  10,  25, 22,  22, 17, 20, 16,   6, 16, 15, 20, 14,  18, 24,335,
	 1517};

static void hm_constr_tree(struct huffman *hf);
static void hm_init(struct huffman *hf);
static void hm_setbits(struct huffman *hf, struct huffman_node *node,
                                                      int bits, unsigned depth);
static void hm_setbits(struct huffman *hf, struct huffman_node *node,
                                                       int bits, unsigned depth)
{
	if(node->leafs[1] != 0xffff)
		hm_setbits(hf, &hf->nodes[node->leafs[1]],
		                                      bits|(1<<depth), depth+1);
	if(node->leafs[0] != 0xffff)
		hm_setbits(hf, &hf->nodes[node->leafs[0]], bits, depth+1);
	if(node->num_bits)
	{
		node->bits = bits;
		node->num_bits = depth;
	}
}

static void hm_bblsort(struct huffman_cnode **ppList, int Size)
{
	int changed = 1;
	int i;
	struct huffman_cnode *cntmp;
	while(changed)
	{
		changed = 0;
		for(i = 0; i < Size-1; i++)
		{
			if(ppList[i]->freq < ppList[i+1]->freq)
			{
				cntmp = ppList[i];
				ppList[i] = ppList[i+1];
				ppList[i+1] = cntmp;
				changed = 1;
			}
		}
		Size--;
	}
}

static void hm_constr_tree(struct huffman *hf)
{
	struct huffman_cnode left_stor[HUFFMAN_MAX_SYMBOLS];
	struct huffman_cnode *left[HUFFMAN_MAX_SYMBOLS];
	int left_cnt = HUFFMAN_MAX_SYMBOLS;
	int i;

	/* add the symbols */
	for(i = 0; i < HUFFMAN_MAX_SYMBOLS; i++)
	{
		hf->nodes[i].num_bits = 0xFFFFFFFF;
		hf->nodes[i].symbol = i;
		hf->nodes[i].leafs[0] = 0xffff;
		hf->nodes[i].leafs[1] = 0xffff;

		if(i == HUFFMAN_EOF_SYMBOL)
			left_stor[i].freq = 1;
		else
			left_stor[i].freq = hm_freqtbl[i];
		left_stor[i].node_id = i;
		left[i] = &left_stor[i];
	}
	hf->num_nodes = HUFFMAN_MAX_SYMBOLS;
	/* construct the table */
	while(left_cnt > 1)
	{
		hm_bblsort(left, left_cnt);

		hf->nodes[hf->num_nodes].num_bits = 0;
		hf->nodes[hf->num_nodes].leafs[0] = left[left_cnt-1]->node_id;
		hf->nodes[hf->num_nodes].leafs[1] = left[left_cnt-2]->node_id;
		left[left_cnt-2]->node_id = hf->num_nodes;
		left[left_cnt-2]->freq = left[left_cnt-1]->freq
		                       + left[left_cnt-2]->freq;
		hf->num_nodes++;
		left_cnt--;
	}
	/* set start node */
	hf->start_node = &hf->nodes[hf->num_nodes-1];
	/* build symbol bits */
	hm_setbits(hf, hf->start_node, 0, 0);
}

static void hm_init(struct huffman *hf)
{
	int i;

	/* make sure to cleanout every thing */
	memset(hf, 0, sizeof(*hf));

	/* construct the tree */
	hm_constr_tree(hf);

	/* build decode LUT */
	for(i = 0; i < HUFFMAN_LUTSIZE; i++)
	{
		unsigned bits = i;
		int k;
		struct huffman_node *node = hf->start_node;
		for(k = 0; k < HUFFMAN_LUTBITS; k++)
		{
			node = &hf->nodes[node->leafs[bits&1]];
			bits >>= 1;

			if(!node)
				break;

			if(node->num_bits)
			{
				hf->decode_lut[i] = node;
				break;
			}
		}

		if(k == HUFFMAN_LUTBITS)
			hf->decode_lut[i] = node;
	}
}

int tw_hm_decompr(const void *in, int in_sz, void *out, int out_sz)
{
	/* setup buffer pointers */
	unsigned char *dst;
	unsigned char *src;
	unsigned char *dst_end;
	unsigned char *src_end;

	unsigned bits = 0;
	unsigned bit_cnt = 0;

	struct huffman_node *eof = &hm.nodes[HUFFMAN_EOF_SYMBOL];
	struct huffman_node *node = 0;

	dst = (unsigned char *)out;
	src = (unsigned char *)in;
	dst_end = dst + out_sz;
	src_end = src + in_sz;

	if (!hm_initialized)
		hm_init(&hm);

	while(1)
	{
		/* {A} try to load a node now, this will reduce dependency at
		 * location {D} */
		node = 0;
		if(bit_cnt >= HUFFMAN_LUTBITS)
			node = hm.decode_lut[bits&HUFFMAN_LUTMASK];

		/* {B} fill with new bits */
		while(bit_cnt < 24 && src != src_end)
		{
			bits |= (*src++) << bit_cnt;
			bit_cnt += 8;
		}

		/*{C}load symbol now if we didn't that earlier at location {A}*/
		if(!node)
			node = hm.decode_lut[bits&HUFFMAN_LUTMASK];

		if(!node)
			return -1;

		/* {D} check if we hit a symbol already */
		if(node->num_bits)
		{
			/* remove the bits for that symbol */
			bits >>= node->num_bits;
			bit_cnt -= node->num_bits;
		}
		else
		{
			/* remove the bits that the lut checked up for us */
			bits >>= HUFFMAN_LUTBITS;
			bit_cnt -= HUFFMAN_LUTBITS;

			/* walk the tree bit by bit */
			while(1)
			{
				/* traverse tree */
				node = &hm.nodes[node->leafs[bits&1]];

				/* remove bit */
				bit_cnt--;
				bits >>= 1;

				/* check if we hit a symbol */
				if(node->num_bits)
					break;

				/* no more bits, decoding error */
				if(bit_cnt == 0)
					return -1;
			}
		}

		/* check for eof */
		if(node == eof)
			break;

		/* output character */
		if(dst == dst_end)
			return -1;
		*dst++ = node->symbol;
	}

	/* return the size of the decompressed buffer */
	return (int)(dst - (const unsigned char *)out);
}
#undef HUFFMAN_EOF_SYMBOL
#undef HUFFMAN_MAX_SYMBOLS
#undef HUFFMAN_MAX_NODES
#undef HUFFMAN_LUTBITS
#undef HUFFMAN_LUTSIZE
#undef HUFFMAN_LUTMASK
