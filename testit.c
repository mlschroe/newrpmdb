#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "rpmpkg.h"
#include "rpmidx.h"

#if 1
#define rpmpkgPut rpmpkgPutLZO
#define rpmpkgGet rpmpkgGetLZO
#endif

#define TAG_NAME		1000
#define TAG_BASENAMES           1117
#define TAG_PROVIDENAME         1047
#define TAG_REQUIRENAME         1049
#define TAG_CONFLICTNAME        1054
#define TAG_OBSOLETENAME        1090
#define TAG_TRIGGERNAME         1066


typedef struct rpmhead {
  int cnt; 
  int dcnt;
  unsigned char *dp; 
} RpmHead;


static inline unsigned char *
headfindtag(RpmHead *h, int tag) 
{
  unsigned int i;
  unsigned char *d, taga[4];
  d = h->dp - 16;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag; 
  for (i = 0; i < h->cnt; i++, d -= 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      return d;
  return 0;
}

static char *
headstring(RpmHead *h, int tag) 
{
  unsigned int o;
  unsigned char *d = headfindtag(h, tag);
  /* 6: STRING, 9: I18NSTRING */
  if (!d || d[4] != 0 || d[5] != 0 || d[6] != 0 || (d[7] != 6 && d[7] != 9))
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  if (o >= h->dcnt)
    return 0;
  return (char *)h->dp + o;
}

static char **
headstringarray(RpmHead *h, int tag, int *cnt)
{
  unsigned int i, o;
  unsigned char *d = headfindtag(h, tag);
  char **r;

  if (!d || d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 8)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  i = d[12] << 24 | d[13] << 16 | d[14] << 8 | d[15];
  r = calloc(i ? i : 1, sizeof(char *));
  if (cnt)
    *cnt = i;
  d = h->dp + o;
  for (o = 0; o < i; o++)
    {
      r[o] = (char *)d;
      if (o + 1 < i)
        d += strlen((char *)d) + 1;
      if (d >= h->dp + h->dcnt)
        {
          free(r);
          return 0;
        }
    }
  return r;
}

static void
rpmheadfromblob(RpmHead *h, unsigned char *blob, unsigned int blobl)
{
  if (blob[0] != 0x8e)
    {
      fprintf(stderr, "not a rpm header\n");
      exit(1);
    }
  h->cnt = blob[8] << 24 | blob[9] << 16 | blob[10] << 8 | blob[11];
  h->dcnt = blob[9] << 24 | blob[10] << 16 | blob[11] << 8 | blob[12];
  h->dp = blob + 16 + h->cnt * 16;
}

struct idb {
  char *name;
  rpmidxdb idxdb;
  int tag;
  int isarray;
} myidbs[] = {
  { "Basenames.db", 0, TAG_BASENAMES, 1 },
  { "Name.db", 0, TAG_NAME, 0 },
  { "Provides.db", 0, TAG_PROVIDENAME, 1 },
  { "Requires.db", 0, TAG_REQUIRENAME, 1 },
  { "Conflicts.db", 0, TAG_CONFLICTNAME, 1 },
  { "Obsoletes.db", 0, TAG_OBSOLETENAME, 1 },
  { "Triggers.db", 0, TAG_TRIGGERNAME, 1 },
  { 0, 0, 0, 0 }
};

/* assumes we don't overwrite! */
void
writeheader(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char *blob, unsigned int blobl)
{
  RpmHead h;
  char **bn;
  char *s[1];
  int i, cnt;

  rpmheadfromblob(&h, blob, blobl);

  rpmpkgLock(pkgdb, 1);
  rpmpkgSetIdxGeneration(pkgdb);
  if (rpmpkgPut(pkgdb, pkgidx, blob, blobl))
    {
      perror("rpmpkgPut");
      exit(1);
    }
  for (i = 0; myidbs[i].name; i++)
    {
      if (myidbs[i].isarray)
        bn = headstringarray(&h, myidbs[i].tag, &cnt);
      else
	{
	  s[0] = headstring(&h, myidbs[i].tag);
	  cnt = 1;
	  bn = s[0] ? s : 0;
	}
      if (bn && cnt)
	{
	  if (rpmidxPut(myidbs[i].idxdb, pkgidx, bn, cnt))
	    {
	      perror("rpmidxPut");
	      exit(1);
	    }
	}
      if (bn && bn != s)
	free(bn);
    }
  rpmpkgClearIdxGeneration(pkgdb);
  for (i = 0; myidbs[i].name; i++) {
    rpmidxUpdateGeneration(myidbs[i].idxdb);
  }
  rpmpkgUnlock(pkgdb, 1);
}

void
eraseheader(rpmpkgdb pkgdb, unsigned int pkgidx)
{
  unsigned char *blob;
  unsigned int blobl;
  int i;

  rpmpkgLock(pkgdb, 1);
  if (rpmpkgGet(pkgdb, pkgidx, &blob, &blobl))
    {
      perror("rpmpkgGet");
      exit(1);
    }
  if (blob)
    {
      RpmHead h;
      char **bn;
      int cnt;
      char *s[1];

      rpmpkgSetIdxGeneration(pkgdb);
      rpmheadfromblob(&h, blob, blobl);
      for (i = 0; myidbs[i].name; i++)
	{
	  if (myidbs[i].isarray)
	    bn = headstringarray(&h, myidbs[i].tag, &cnt);
	  else
	    {
	      s[0] = headstring(&h, myidbs[i].tag);
	      cnt = 1;
	      bn = s[0] ? s : 0;
	    }
	  if (bn && cnt)
	    {
	      if (rpmidxErase(myidbs[i].idxdb, pkgidx, bn, cnt))
		{
		  perror("rpmidxErase");
		  exit(1);
		}
	    }
	  if (bn && bn != s)
	    free(bn);
	}
      if (rpmpkgErase(pkgdb, pkgidx))
	{
	  perror("rpmpkgErase");
	  exit(1);
	}
      rpmpkgClearIdxGeneration(pkgdb);
      for (i = 0; myidbs[i].name; i++)
	rpmidxUpdateGeneration(myidbs[i].idxdb);
    }
  rpmpkgUnlock(pkgdb, 1);
}

void
lookup_basename(rpmpkgdb pkgdb, char *key)
{
  unsigned int *hits;
  unsigned int nhits;
  unsigned int i;
  if (rpmidxGet(myidbs[0].idxdb, key, &hits, &nhits))
    {
      perror("rpmidxGet");
      exit(1);
    }
  if (!hits)
    return;
  for (i = 0; i < nhits; i += 2)
    {
      printf("hit for %s: %d %d\n", key, hits[i], hits[i + 1]);
    }
  free(hits);
}

void
list_conflicts(rpmpkgdb pkgdb)
{
  char **conf;
  unsigned int nconf, i;
  if (rpmidxList(myidbs[4].idxdb, &conf, &nconf))
    {
      perror("rpmidxList");
      exit(1);
    }
  printf("found %d conflicts\n", nconf);
  for (i = 0; i < nconf; i++)
    {
      printf("conflict %s\n", conf[i]);
      free(conf[i]);
    }
  free(conf);
}

unsigned int 
timems(unsigned int subtract)
{
  struct timeval tv; 
  unsigned int r;

  if (gettimeofday(&tv, 0)) 
    return 0;
  r = (((unsigned int)tv.tv_sec >> 16) * 1000) << 16; 
  r += ((unsigned int)tv.tv_sec & 0xffff) * 1000;
  r += (unsigned int)tv.tv_usec / 1000;
  return r - subtract;
}

void
drop_caches()
{
#if 0
  int fd;
  printf("dropping caches...\n");
  sync();
  if ((fd = open("/proc/sys/vm/drop_caches", O_WRONLY)) < 0)
    {
      perror("proc");
      exit(1);
    }
  if (write(fd, "3\n", 2) != 2) {
      perror("proc write");
      exit(1);
  }
  close(fd);
  printf("caches dropped.\n");
#endif
}

struct hdr {
  unsigned int idx;
  unsigned char *blob;
  unsigned int blobl;
} *hdrs;
int nhdrs;

void
shuffle()
{
  int i;
  if (nhdrs < 2)
    return;
  for (i = 0; i < nhdrs - 1; i++)
    {
      int y = (random() % (nhdrs - i)) + i;
      if (i != y)
	{
	  struct hdr tmp;
	  tmp = hdrs[i];
	  hdrs[i] = hdrs[y];
	  hdrs[y] = tmp;
	}
    }
}

void
renumber(int offset)
{
  int i;
  for (i = 0; i < nhdrs; i++)
    hdrs[i].idx = i + 1 + offset;
}

int
main()
{
  int i;
  unsigned char x[4];
  unsigned int now;
  rpmpkgdb pkgdb;

  printf("reading headers\n");
  hdrs = calloc(3000, sizeof(struct hdr));
  for (i = 0; i < 3000; i++)
    {
      unsigned int l;
      int r = read(0, x, 4);
      if (r < 0)
	{
	  perror("l read\n");
	  exit(1);
	}
      if (r == 0)
	break;
      l = x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3];
      if (l > 10 * 1024 * 1024 || !l) {
	fprintf(stderr, "bad header size\n");
	exit(1);
      }
      hdrs[i].idx = i + 1;
      hdrs[i].blob = malloc(l);
      hdrs[i].blobl = l;
      if (read(0, hdrs[i].blob, l) != l)
	{
	  perror("header read");
	  exit(1);
	}
    }
  nhdrs = i;
  printf("found %d headers\n", nhdrs);

  printf("opening database\n");
  unlink("Packages.db");
  if (rpmpkgOpen(&pkgdb, "Packages.db", O_RDWR|O_CREAT, 0666))
    {
      perror("rpmpkgOpen");
      exit(1);
    }
  for (i = 0; myidbs[i].name; i++)
    {
      unlink(myidbs[i].name);
      if (rpmidxOpen(&myidbs[i].idxdb, pkgdb, myidbs[i].name, O_RDWR|O_CREAT, 0666))
	{
	  perror("rpmidxOpen");
	  exit(1);
	}
    }
  /* disable fsync */
  rpmpkgSetFsync(pkgdb, 0);

#if 0
  drop_caches();
  shuffle();
  printf("writing into database\n");
#endif
  now = timems(0);
  
  for (i = 0; i < nhdrs; i++)
    {
#if 0
      if (rpmpkgPut(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl))
	{
	  perror("rpmpkgPut");
	  exit(1);
	}
#else
      writeheader(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
#endif
    }
  printf("writing took %d ms\n", timems(now));

  lookup_basename(pkgdb, "screen");
  list_conflicts(pkgdb);

  drop_caches();
  shuffle();
  printf("reading all headers from database\n");
  now = timems(0);
  for (i = 0; i < nhdrs; i++)
    {
      unsigned char *blob;
      unsigned int blobl;
      if (rpmpkgGet(pkgdb, hdrs[i].idx, &blob, &blobl))
	{
	  perror("rpmpkgGet");
	  exit(1);
	}
      if (blobl != hdrs[i].blobl)
	{
	  perror("rpmpkgGet: wrong header");
	  exit(1);
	}
    }
  printf("reading took %d ms\n", timems(now));

  drop_caches();
  shuffle();

  renumber(nhdrs);
  printf("simmulating distribution upgrade\n");
  now = timems(0);
#if 0
  /* simulating suse update */
  for (i = 0; i < nhdrs; i++)
    {
#if 0
      if (rpmpkgPut(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl))
	{
	  perror("rpmpkgPut");
	  exit(1);
	}
      if (rpmpkgErase(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgErase");
	  exit(1);
	}
#else
      writeheader(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
      eraseheader(pkgdb, hdrs[i].idx - nhdrs);
#endif
    }
#else
  /* simulating redhat update */
#if 0
  for (i = 0; i < nhdrs; i++)
    {
      if (rpmpkgPut(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl))
	{
	  perror("rpmpkgPut");
	  exit(1);
	}
    }
  for (i = 0; i < nhdrs; i++)
    {
      if (rpmpkgErase(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgErase");
	  exit(1);
	}
    }
#else
  for (i = 0; i < nhdrs; i++)
    writeheader(pkgdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
  for (i = 0; i < nhdrs; i++)
    eraseheader(pkgdb, hdrs[i].idx - nhdrs);
#endif
#endif
  printf("upgrade took %d ms\n", timems(now));

  printf("erasing all packages\n");
  shuffle();
  now = timems(0);
  for (i = 0; i < nhdrs; i++)
    {
#if 0
      if (rpmpkgErase(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgErase");
	  exit(1);
	}
#else
      eraseheader(pkgdb, hdrs[i].idx);
#endif
    }
  printf("erase took %d ms\n", timems(now));

  exit(0);
}
