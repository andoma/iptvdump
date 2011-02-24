/*
 *  Transport stream logger
 *  Copyright (C) 2007 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/time.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "ts.h"

extern int pcr_analysis;


static int64_t
get_ts(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}

#define NOPTS_VALUE INT64_MIN

#define PIDLOGFMT "[%10s @ %-4d]"
#define PIDLOGARG st->st_name, st->st_pid

static uint32_t psi_crc32(uint8_t *data, size_t datalen);

#define getu32(b, l) ({						\
  uint32_t x = (b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);	\
  b+=4;								\
  l-=4; 							\
  x;								\
})

#define getu16(b, l) ({				\
  uint16_t x = (b[0] << 8 | b[1]);		\
  b+=2;						\
  l-=2;						\
  x;						\
})

#define getu8(b, l) ({				\
  uint8_t x = b[0];				\
  b+=1;						\
  l-=1;						\
  x;						\
})

#define getpts(b, l) ({					\
  int64_t _pts;						\
  _pts = (int64_t)((getu8(b, l) >> 1) & 0x07) << 30;	\
  _pts |= (int64_t)(getu16(b, l) >> 1) << 15;		\
  _pts |= (int64_t)(getu16(b, l) >> 1);			\
  _pts;							\
})


#define MMAX(a, b) ((a) > (b) ? (a) : (b))
#define MMIN(a, b) ((a) < (b) ? (a) : (b))

#define PSI_SECTION_SIZE 4096

typedef struct stream {

  int st_pid;
  char *st_name;

  int st_cc;
  int st_cc_valid;

  enum {
    ST_NONE,
    ST_TABLE,
    ST_PES,
  } st_type;

  void (*st_callback)(struct stream *st, int tableid, uint8_t *data, int len);

  int st_table_crc;
  int st_buffer_offset;
  int st_buffer_size;
  uint8_t *st_buffer;


  int64_t st_pes_start;
  const char *st_datainfo;

} stream_t;

static int pcr_pid;
static int service_id;
static int64_t pcrclk = NOPTS_VALUE;
static int64_t pcrclkrt;

static stream_t *streamvec[8192];

/**
 *
 */
static stream_t *
add_table(void (*callback)(struct stream *st, int tid, uint8_t *data, int len),
	  int pid, int crc, const char *name)
{
  stream_t *st;

  if(streamvec[pid] != NULL)
    return streamvec[pid];

  st = streamvec[pid] = calloc(1, sizeof(stream_t));
  st->st_pid = pid;
  st->st_name = strdup(name);
  st->st_type = ST_TABLE;
  st->st_table_crc = crc;
  st->st_callback = callback;
  fprintf(stderr, "PID: "PIDLOGFMT" Added\n", PIDLOGARG);

  return st;
}


/**
 *
 */
static stream_t *
add_pes(void (*callback)(struct stream *st, int tid, uint8_t *data, int len),
	  int pid, const char *name)
{
  stream_t *st;

  if(streamvec[pid] != NULL)
    return streamvec[pid];

  st = streamvec[pid] = calloc(1, sizeof(stream_t));
  st->st_pid = pid;
  st->st_name = strdup(name);
  st->st_type = ST_PES;
  st->st_callback = callback;
  fprintf(stderr, "PID: "PIDLOGFMT" Added \n", PIDLOGARG);
  return st;
}


/** 
 * MPEG2VIDEO parser
 */

#define MP2V_I_FRAME 1
#define MP2V_P_FRAME 2
#define MP2V_B_FRAME 3

static void
decode_mpeg2video(struct stream *st, int tableid, uint8_t *buf, int len)
{
  uint32_t sc;
  int frame;
  sc = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
  
  if(sc == 0x100) {
    frame = (buf[5] >> 3) & 7;
  } else {
    frame = MP2V_I_FRAME;
  }
 
  switch(frame) {
  case MP2V_I_FRAME:
    printf("I-FRAME Picture start");
    st->st_datainfo = "I-FRAME Picture end  ";
    break;
  case MP2V_P_FRAME:
    printf("P-FRAME Picture start");
    st->st_datainfo = "P-FRAME Picture end  ";
    break;
  case MP2V_B_FRAME:
    printf("B-FRAME Picture start");
    st->st_datainfo = "B-FRAME Picture end  ";
    break;
  }

  printf("\n");
}

/** 
 * MPEG2AUDIO parser
 */
static void
decode_mpeg2audio(struct stream *st, int tableid, uint8_t *ptr, int len)
{
  printf("\n");
}

/** 
 * AC3 parser
 */
static void
decode_ac3(struct stream *st, int tableid, uint8_t *ptr, int len)
{
  printf("\n");
}



/** 
 * h264 parser
 */
static void
decode_h264(struct stream *st, int tableid, uint8_t *ptr, int len)
{
  printf("NAL unit start");
  st->st_datainfo = "NAL unit end  ";
  printf("\n");
}


/** 
 * PES (header) parser
 */

static void
decode_pes_hdr(struct stream *st, uint8_t *buf, int len)
{
  uint32_t startcode;
  uint16_t plen;
  uint8_t hdr, flags, hlen;
  int64_t dts = NOPTS_VALUE, pts = NOPTS_VALUE;
  int64_t rtdelta, pcr, rt, v;

  if(len < 9) {
    fprintf(stderr, "Too short PES packet (%d bytes)\n", len);
    return;
  }

  startcode = getu32(buf, len);
  plen      = getu16(buf, len);
  hdr       = getu8(buf,  len);
  flags     = getu8(buf,  len);
  hlen      = getu8(buf,  len);
  
  if(len < hlen) {
    fprintf(stderr, "PES: "PIDLOGFMT" header length too long\n", PIDLOGARG);
    return;
  }
  if((hdr & 0xc0) != 0x80) {
    fprintf(stderr, "PES: "PIDLOGFMT" is not MPEG2 systems\n", PIDLOGARG);
    return;
  }

  if((flags & 0xc0) == 0xc0) {
    if(hlen < 10) {
      fprintf(stderr, "PES: "PIDLOGFMT" PTS/DTS does not fit in header", 
	      PIDLOGARG);
      return;
    }
  
    pts = getpts(buf, len);
    dts = getpts(buf, len);
    hlen -= 10;
  } else if((flags & 0xc0) == 0x80) {
    if(hlen < 5) {
      fprintf(stderr, "PES: "PIDLOGFMT" PTS does not fit in header", 
	      PIDLOGARG);
      return;
    }
    dts = pts = getpts(buf, len);
    hlen -= 5;
  }

  buf += hlen;
  len -= hlen;
  rtdelta = 0;

  printf("PES: "PIDLOGFMT" %10"PRId64" %10"PRId64" | ", PIDLOGARG, dts, pts);

  rt = get_ts();

  if(pcrclk != NOPTS_VALUE) {
    rtdelta = rt - pcrclkrt;
    pcr = pcrclk + ((double)rtdelta / (1000000. / 90000.));
    v = (dts - pcr);// & 0x1ffffffffULL;
    printf("%10"PRId64" | ", v);
  } else {
    printf("           | ");
  }

  if(pcrclk != NOPTS_VALUE) {
    rtdelta = rt - pcrclkrt;
    pcr = pcrclk + ((double)rtdelta / (1000000. / 90000.));
    v = (pts - pcr);// & 0x1ffffffffULL;
    printf("%10"PRId64" | ", v);
  } else {
    printf("           | ");
  }


  st->st_pes_start = rt;

  st->st_callback(st, 0, buf, len);
}

/** 
 * PES packet done
 */
static void
decode_pes_done(struct stream *st, uint8_t *buf, int len)
{
  int64_t pktdelta, bps, rt;

  if(st->st_datainfo == NULL)
    return;

  printf("PES: "PIDLOGFMT"                                                 | ", PIDLOGARG);
  rt = get_ts();
  pktdelta = rt - st->st_pes_start;

  bps = st->st_buffer_offset * 1000000LL / pktdelta;

  printf("%s %6d bytes, %"PRId64" us (%"PRId64" bytes / sec)\n",
	 st->st_datainfo,
	 st->st_buffer_offset, pktdelta, bps);
}


/** 
 * PMT parser, from ISO 13818-1 and ETSI EN 300 468
 */
static void
decode_pmt(struct stream *st, int tableid, uint8_t *ptr, int len)
{
  int pid;
  int dllen, x, i;
  uint8_t dtag, dlen, estype;
  const char *name = NULL;

  void (*cb)(struct stream *st, int tid, uint8_t *data, int len);

  if(len < 9) {
    fprintf(stderr, "ERR: "PIDLOGFMT" Invalid PMT length %d\n",
	    PIDLOGARG, len);
    return;
  }

  fprintf(stderr, "PMT: Received\n");

  service_id = ptr[0] << 8 | ptr[1];
  x          = (ptr[5] & 0x1f) << 8 | ptr[6];
  dllen      = (ptr[7] & 0xf) << 8 | ptr[8];

  if(pcr_pid == 0) {
    pcr_pid = x;
    fprintf(stderr, "PCR: Arriving on pid %d\n", x);
  }

  ptr += 9;
  len -= 9;

  while(dllen > 1) {
    dtag = ptr[0];
    dlen = ptr[1];

    len -= 2; ptr += 2; dllen -= 2; 
    if(dlen > len) {
      fprintf(stderr, "ERR: "PIDLOGFMT" table error, tag exceeds length\n",
	      PIDLOGARG);
      return;
    }
    len -= dlen; ptr += dlen; dllen -= dlen;
  }
  
  while(len >= 5) {
    estype  = ptr[0];
    pid     = (ptr[1] & 0x1f) << 8 | ptr[2];
    dllen   = (ptr[3] & 0xf) << 8 | ptr[4];

    ptr += 5;
    len -= 5;
    
    switch(estype) {
    case 0x01:
    case 0x02:
      cb = decode_mpeg2video;
      name = "Mpeg2Video";
      break;

    case 0x03:
    case 0x04:
    case 0x81:
      cb = decode_mpeg2audio;
      name = "Mpeg2Audio";
      break;
    case 0x1b:
      cb = decode_h264;
      name = "h264";
      break;
    default:
      cb = NULL;
    }

    
    while(dllen > 1) {
      dtag = ptr[0];
      dlen = ptr[1];

      len -= 2; ptr += 2; dllen -= 2; 
      if(dlen > len)
	break;

      switch(dtag) {
      case 0x6a: /* AC3 */
	if(estype == 0x06 || estype == 0x81) {
	  cb = decode_ac3;
	  name = "AC3";
	} else {
	  fprintf(stderr, "PMT: PID: %5d: AC3 descriptor on unknown stream type 0x%02x\n", pid, estype);
	}
	break;

      case 0x5:
	if(dlen == 4 && ptr[0] == 'A' && ptr[1] == 'C' && ptr[2] == '-' &&  ptr[3] == '3') {
	  cb = decode_ac3;
	  name = "AC3";
	  break;
	}
	goto unknown;

      default:
      unknown:
	fprintf(stderr, "PMT: PID: %5d: Unknown descriptor 0x%02x\n", pid, dtag);
	fprintf(stderr, "           dump: ");

	for(i = 0; i < dlen; i++) 
	  fprintf(stderr, "%02x.", ptr[i]);
	fprintf(stderr, "\n");
	break;
      }
      len -= dlen; ptr += dlen; dllen -= dlen;
    }

    if(cb == NULL)
      continue;

    add_pes(cb, pid, name);
  }
}


/**
 *
 */
static void
decode_pat(struct stream *st, int tableid, uint8_t *ptr, int len)
{
  int prognum, pid;

  if(len < 5) {
    fprintf(stderr, "ERR: Invalid PAT length %d\n", len);
    return;
  }

  if(tableid != 0) {
    fprintf(stderr, "ERR: PAT does not have tableid == 0\n");
    return;
  }

  fprintf(stderr, "PAT: Received\n");

  ptr += 5;
  len -= 5;

  while(len >= 4) {
    prognum =  ptr[0]         << 8 | ptr[1];
    pid     = (ptr[2] & 0x1f) << 8 | ptr[3];

    if(prognum != 0)
      add_table(decode_pmt, pid, 1, "PMT");

    ptr += 4;
    len -= 4;
  }
}




/**
 *
 */
static void
psi_section_reassemble(stream_t *st, uint8_t *data, int len,  int start)
{
  int remain, a, tsize;

  if(start)
    st->st_buffer_offset = 0;

  if(st->st_buffer_offset < 0)
    return;

  if(st->st_buffer == NULL)
    st->st_buffer = malloc(PSI_SECTION_SIZE);

  remain = PSI_SECTION_SIZE - st->st_buffer_offset;

  a = MMAX(0, MMIN(remain, len));

  memcpy(st->st_buffer + st->st_buffer_offset, data, a);
  st->st_buffer_offset += a;
  tsize = 3 + (((st->st_buffer[1] & 0xf) << 8) | st->st_buffer[2]);
  if(st->st_buffer_offset < tsize)
    return;

  if(st->st_table_crc && psi_crc32(st->st_buffer, tsize)) {
    fprintf(stderr, "ERR: "PIDLOGFMT" section CRC32 error\n", PIDLOGARG);
    return;
  }
  len = tsize - (st->st_table_crc ? 4 : 0);

  if(len < 3) {
    fprintf(stderr, "ERR: "PIDLOGFMT" section length error (%d)\n",
	    PIDLOGARG, len);
    return;
  }
  st->st_callback(st, st->st_buffer[0], st->st_buffer + 3, len - 3);
}




/**
 *
 */
void
process_ts_packet(uint8_t *tsb)
{
  uint16_t pid;
  stream_t *st;
  int afl = 0, afc, cc, err = 0, pusi, len;
  int64_t pcr;

  if(tsb[0] != 0x47) {
    fprintf(stderr, "ERR: MPEG TS Marker invalid 0x%02x, expected 0x47\n",
	    tsb[0]);
    return;
  }

  pid = ((tsb[1] & 0x1f) << 8) | tsb[2];
  
  if(pid == 0)
    add_table(decode_pat, 0, 1, "PAT");
  
  if((st = streamvec[pid]) == NULL)
    return;

  afc = (tsb[3] >> 4) & 3;
  if(afc & 1) {
    cc = tsb[3] & 0xf;
    if(st->st_cc_valid && cc != st->st_cc) {
      err = 1;
      fprintf(stderr, "ERR: "PIDLOGFMT" CC error\n", PIDLOGARG);
    }
    st->st_cc_valid = 1;
    st->st_cc = (cc + 1) & 0xf;
  }


  if(afc & 2) {
    afl = tsb[4] + 1;
    if(afl > 1) {
      if(tsb[5] & 0x10) {
	pcr  = (uint64_t)tsb[6] << 25;
	pcr |= (uint64_t)tsb[7] << 17;
	pcr |= (uint64_t)tsb[8] << 9;
	pcr |= (uint64_t)tsb[9] << 1;
	pcr |= (uint64_t)tsb[10] >> 7 & 0x01;

	printf("PCR: "PIDLOGFMT" %10"PRId64"d\n", PIDLOGARG, pcr);
	pcrclk = pcr;
	pcrclkrt = get_ts();
      }
    }
  }

  pusi = tsb[1] & 0x40;
  afl += 4;

  switch(st->st_type) {

  default:
    return;
    
  case ST_TABLE:
    if(err || afl >= 188) {
      st->st_buffer_offset = -1;
      return;
    }
    
    if(pusi) {
      len = tsb[afl++];
      if(len > 0) {
	if(len > 188 - afl)
	  return;
	psi_section_reassemble(st, tsb + afl, len, 0);
	afl += len;
      }
    }
    
    psi_section_reassemble(st, tsb + afl, 188 - afl, pusi);
    break;

  case ST_PES:
    len = 188 - afl;
    if(len == 0)
      break;

    if(pusi) {
      if(st->st_buffer_offset) {
	decode_pes_done(st, st->st_buffer, st->st_buffer_offset);
	st->st_buffer_offset = 0;
      }
    }

    if(st->st_buffer_offset + len > st->st_buffer_size) {
      st->st_buffer_size += 4096 + len * 4;
      st->st_buffer = realloc(st->st_buffer, st->st_buffer_size);
    }
    memcpy(st->st_buffer + st->st_buffer_offset, tsb + afl, len);
    
    if(st->st_buffer_offset == 0) {
      decode_pes_hdr(st, st->st_buffer, len);
    }
    st->st_buffer_offset += len;
    break;
  }
}




/*
 * CRC32 
 */
static uint32_t crc_tab[256] = {
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
  0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
  0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
  0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
  0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
  0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
  0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
  0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
  0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
  0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
  0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
  0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
  0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
  0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
  0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
  0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
  0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
  0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
  0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
  0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
  0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
  0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

static uint32_t
psi_crc32(uint8_t *data, size_t datalen)
{
  uint32_t crc = 0xffffffff;

  while(datalen--)
    crc = (crc << 8) ^ crc_tab[((crc >> 24) ^ *data++) & 0xff];

  return crc;
}
