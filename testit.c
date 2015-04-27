#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include "rpmpkg.h"
#include "rpmidx.h"
#include "rpmxdb.h"

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
  h->dcnt = blob[12] << 24 | blob[13] << 16 | blob[14] << 8 | blob[15];
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
  { "Requires.db", 0, TAG_REQUIRENAME, 2 },
  { "Conflicts.db", 0, TAG_CONFLICTNAME, 1 },
  { "Obsoletes.db", 0, TAG_OBSOLETENAME, 1 },
  { "Triggers.db", 0, TAG_TRIGGERNAME, 1 },
#if 0
  { "Filerequires.db", 0, TAG_REQUIRENAME, 3 },
#endif
  { 0, 0, 0, 0 }
};

void filterheadelements(char **ell, int cnt, int type)
{
  int i;
  for (i = 0; i < cnt; i++)
    {
      char *el = ell[i];
      switch(type)
	{
	case 2:
	  /* crude imitation of looking at the sense flags */
	  if (!strncmp(el, "rpmlib(", 7))
	    ell[i] = 0;
	  break;
	case 3:
	  if (*el != '/')
	    ell[i] = 0;
	  break;
	default:
	  break;
	}
    }
}

/* assumes we don't overwrite! */
void
writeheader(rpmpkgdb pkgdb, rpmxdb xdb, unsigned int pkgidx, unsigned char *blob, unsigned int blobl)
{
  RpmHead h;
  char **bn;
  char *s[1];
  int i, cnt;

  rpmheadfromblob(&h, blob, blobl);

  rpmpkgLock(pkgdb, 1);
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
	  int j;
	  if (myidbs[i].isarray > 1)
	    filterheadelements(bn, cnt, myidbs[i].isarray);
	  for (j = 0; j < cnt; j++)
	    if (bn[j] && rpmidxPut(myidbs[i].idxdb, (unsigned char *)bn[j], strlen(bn[j]), pkgidx, j))
	      {
	        perror("rpmidxPut");
	        exit(1);
	      }
	}
      if (bn && bn != s)
	free(bn);
    }
  rpmpkgUnlock(pkgdb, 1);
}

void
eraseheader(rpmpkgdb pkgdb, rpmxdb xdb, unsigned int pkgidx)
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
	      int j;
	      if (myidbs[i].isarray > 1)
		filterheadelements(bn, cnt, myidbs[i].isarray);
	      for (j = 0; j < cnt; j++)
	        if (bn[j] && rpmidxDel(myidbs[i].idxdb, (unsigned char *)bn[j], strlen(bn[j]), pkgidx, j))
		  {
		    perror("rpmidxDel");
		    exit(1);
		  }
	    }
	  if (bn && bn != s)
	    free(bn);
	}
      free(blob);
      if (rpmpkgDel(pkgdb, pkgidx))
	{
	  perror("rpmpkgDel");
	  exit(1);
	}
    }
  rpmpkgUnlock(pkgdb, 1);
}

void
lookup_basename(rpmpkgdb pkgdb, char *key)
{
  unsigned int *hits;
  unsigned int nhits;
  unsigned int i;
  if (rpmidxGet(myidbs[0].idxdb, (unsigned char *)key, strlen(key), &hits, &nhits))
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
  unsigned int *conf;
  unsigned int nconf, i;
  unsigned char *data;

  if (rpmidxList(myidbs[4].idxdb, &conf, &nconf, &data))
    {
      perror("rpmidxList");
      exit(1);
    }
  printf("found %d conflicts\n", nconf / 2);
  for (i = 0; i < nconf; i += 2)
    printf("conflict %s [%d]\n", data + conf[i], conf[i + 1]);
  free(conf);
  free(data);
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

void
stats(rpmpkgdb pkgdb, rpmxdb xdb)
{
  int i;
  rpmpkgStats(pkgdb);
  if (xdb)
    rpmxdbStats(xdb);
  for (i = 0; myidbs[i].name; i++)
    rpmidxStats(myidbs[i].idxdb);
}

int
main()
{
  int i;
  unsigned char x[4];
  unsigned int now;
  rpmpkgdb pkgdb;
  rpmxdb xdb = 0;

  srandom((unsigned int)time(0) + (unsigned int)getpid() * 50);
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
#if 1
  unlink("Packages.db");
#endif
  if (rpmpkgOpen(&pkgdb, "Packages.db", O_RDWR|O_CREAT, 0666))
    {
      perror("rpmpkgOpen");
      exit(1);
    }
#if 1
#if 1
  unlink("Index.db");
#endif
  if (rpmxdbOpen(&xdb, pkgdb, "Index.db", O_RDWR|O_CREAT, 0666))
    {
      perror("rpmxdbOpen");
      exit(1);
    }
  for (i = 0; myidbs[i].name; i++)
    {
      if (rpmidxOpenXdb(&myidbs[i].idxdb, pkgdb, xdb, myidbs[i].tag))
	{
	  perror("rpmidxOpen");
	  exit(1);
	}
    }
#else
  for (i = 0; myidbs[i].name; i++)
    {
      unlink(myidbs[i].name);
      if (rpmidxOpen(&myidbs[i].idxdb, pkgdb, myidbs[i].name, O_RDWR|O_CREAT, 0666))
	{
	  perror("rpmidxOpen");
	  exit(1);
	}
    }
#endif
  /* disable fsync */
  rpmpkgSetFsync(pkgdb, 0);

  shuffle();
#if 0
  drop_caches();
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
      writeheader(pkgdb, xdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
#endif
    }
  printf("writing took %d ms\n", timems(now));

#if 0
  lookup_basename(pkgdb, "screen");
  list_conflicts(pkgdb);
#endif
#if 0
  stats(pkgdb, xdb);
#endif

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
      free(blob);
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
      if (rpmpkgDel(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgDel");
	  exit(1);
	}
#else
      writeheader(pkgdb, xdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
      eraseheader(pkgdb, xdb, hdrs[i].idx - nhdrs);
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
      if (rpmpkgDel(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgDel");
	  exit(1);
	}
    }
#else
  for (i = 0; i < nhdrs; i++)
    writeheader(pkgdb, xdb, hdrs[i].idx, hdrs[i].blob, hdrs[i].blobl);
  for (i = 0; i < nhdrs; i++)
    eraseheader(pkgdb, xdb, hdrs[i].idx - nhdrs);
#endif
#endif
  printf("upgrade took %d ms\n", timems(now));
#if 0
  stats(pkgdb, xdb);
#endif

  printf("erasing all packages\n");
  shuffle();
  now = timems(0);
  for (i = 0; i < nhdrs; i++)
    {
#if 0
      if (rpmpkgDel(pkgdb, hdrs[i].idx - nhdrs))
	{
	  perror("rpmpkgDel");
	  exit(1);
	}
#else
      eraseheader(pkgdb, xdb, hdrs[i].idx);
#endif
    }
  printf("erase took %d ms\n", timems(now));
#if 0
  stats(pkgdb, xdb);
#endif


  for (i = 0; myidbs[i].name; i++)
    rpmidxClose(myidbs[i].idxdb);
#if 0
  if (xdb)
    for (i = 0; myidbs[i].name; i++)
      if (rpmidxDelXdb(pkgdb, xdb, myidbs[i].tag))
        {
	  perror("rpmidxDelXdb");
        }
#endif

  if (xdb)
      rpmxdbClose(xdb);
  rpmpkgClose(pkgdb);

  for (i = 0; i < nhdrs; i++)
    free(hdrs[i].blob);
  free(hdrs);

  exit(0);
}
