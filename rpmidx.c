#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "rpmidx.h"

#define RPMRC_FAIL 1
#define RPMRC_OK 0

struct rpmpkgdb_s;

typedef struct rpmidxdb_s {
    rpmpkgdb pkgdb;		/* master database */
    char *filename;
    int fd;                     /* our file descriptor */
    int flags;
    int mode;

    unsigned int pagesize;
    unsigned char *mapped;
    unsigned int mappedlen;

    unsigned int generation;
    unsigned int slotstart;
    unsigned int nslots;
    unsigned int usedslots;
    unsigned int dummyslots;

    unsigned int strstart;
    unsigned int strend;
    unsigned int strexcess;

    unsigned int hmask;
    unsigned int xmask;
} * rpmidxdb;

static inline unsigned int be2h(unsigned char *p) 
{
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline void h2be(unsigned int x, unsigned char *p) 
{
    p[0] = x >> 24; 
    p[1] = x >> 16; 
    p[2] = x >> 8;
    p[3] = x;
}

/*** Header management ***/

#define IDXDB_MAGIC     ('R' << 24 | 'p' << 16 | 'm' << 8 | 'I')

/* header
 * generation
 * nslots
 * usedslots
 * dummyslots
 * xmask
 * strstart
 * strend
 * strexcess
 */

static int rpmidxReadheader(rpmidxdb idxdb)
{
    struct stat stb;

    if (idxdb->mapped) {
	if (be2h(idxdb->mapped + 4) == idxdb->generation) {
	    return RPMRC_OK;
	}
	munmap(idxdb->mapped, idxdb->mappedlen);
	idxdb->mapped = 0;
	idxdb->mappedlen = 0;
    }
    if (fstat(idxdb->fd, &stb)) {
	return RPMRC_FAIL;
    }
    if ((stb.st_size & (idxdb->pagesize - 1)) != 0) {
	return RPMRC_FAIL;
    }
    idxdb->mapped = mmap(0, stb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, idxdb->fd, 0);
    if (idxdb->mapped == MAP_FAILED) {
	idxdb->mapped = 0;
	return RPMRC_FAIL;
    }
    if (be2h(idxdb->mapped) != IDXDB_MAGIC) {
	munmap(idxdb->mapped, stb.st_size);
	idxdb->mapped = 0;
	return RPMRC_FAIL;
    }
    idxdb->mappedlen = stb.st_size;

    idxdb->generation = be2h(idxdb->mapped + 4);
    idxdb->slotstart  = be2h(idxdb->mapped + 8);
    idxdb->nslots     = be2h(idxdb->mapped + 12);
    idxdb->usedslots  = be2h(idxdb->mapped + 16);
    idxdb->dummyslots = be2h(idxdb->mapped + 20);
    idxdb->xmask      = be2h(idxdb->mapped + 24);
    idxdb->strstart   = be2h(idxdb->mapped + 28);
    idxdb->strend     = be2h(idxdb->mapped + 32);
    idxdb->strexcess  = be2h(idxdb->mapped + 36);

    idxdb->hmask = idxdb->nslots - 1;
    return RPMRC_OK;
}

static int rpmidxWriteheader(rpmidxdb idxdb)
{
    if (!idxdb->mapped)
	return RPMRC_FAIL;
    h2be(IDXDB_MAGIC,       idxdb->mapped);
    h2be(idxdb->generation, idxdb->mapped + 4);
    h2be(idxdb->slotstart,  idxdb->mapped + 8);
    h2be(idxdb->nslots,     idxdb->mapped + 12);
    h2be(idxdb->usedslots,  idxdb->mapped + 16);
    h2be(idxdb->dummyslots, idxdb->mapped + 20);
    h2be(idxdb->xmask,      idxdb->mapped + 24);
    h2be(idxdb->strstart,   idxdb->mapped + 28);
    h2be(idxdb->strend,     idxdb->mapped + 32);
    h2be(idxdb->strexcess,  idxdb->mapped + 36);
    return RPMRC_OK;
}

static inline void updateGeneration(rpmidxdb idxdb)
{
   h2be(idxdb->generation, idxdb->mapped + 4);
}

static inline void updateStrend(rpmidxdb idxdb)
{
   h2be(idxdb->strend, idxdb->mapped + 32);
}

static inline void updateStrexcess(rpmidxdb idxdb)
{
   h2be(idxdb->strexcess, idxdb->mapped + 36);
}

static inline void updateUsedslots(rpmidxdb idxdb)
{
   h2be(idxdb->usedslots, idxdb->mapped + 16);
}

static inline void updateDummyslots(rpmidxdb idxdb)
{
   h2be(idxdb->dummyslots, idxdb->mapped + 20);
}


#define MURMUR_M 0x5bd1e995

static unsigned int murmurhash(unsigned char *s, unsigned int l)
{
    unsigned int h =  l * MURMUR_M;

    while (l >= 4) {
	h += s[0] | s[1] << 8 | s[2] << 16 | s[3] << 24;
	h *= MURMUR_M;
	h ^= h >> 16;
	s += 4;
	l -= 4;
    }
    switch (l) {
	case 3:
	    h += s[2] << 16; 
	case 2:
	    h += s[1] << 8;
	case 1:
	    h += s[0];
	    h *= MURMUR_M;
	    h ^= h >> 16;
	default:
	    break;
    }
    h *= MURMUR_M;
    h ^= h >> 10; 
    h *= MURMUR_M;
    h ^= h >> 17; 
    return h;
}


static inline int equalstring(rpmidxdb idxdb, unsigned int off, char *key, int keyl)
{
    keyl++;	/* include trailing 0 */
    if (idxdb->strstart + off + keyl > idxdb->strend)
	return 0;
    if (memcmp(key, idxdb->mapped + idxdb->strstart + off, keyl))
	return 0;
    return 1;
}

static int addstringpage(rpmidxdb idxdb) {
    unsigned char *newaddr;
    if (ftruncate(idxdb->fd, idxdb->mappedlen + idxdb->pagesize))
	return RPMRC_FAIL;
    newaddr = mremap(idxdb->mapped, idxdb->mappedlen, idxdb->mappedlen + idxdb->pagesize, MREMAP_MAYMOVE);
    if (newaddr == MAP_FAILED)
	return RPMRC_FAIL;
    idxdb->mapped = newaddr;
    idxdb->mappedlen += idxdb->pagesize;
    return RPMRC_OK;
}

static int addnewstring(rpmidxdb idxdb, char *key, int keyl, unsigned int *stroffp)
{
    keyl++;	/* include trailing 0 */
    while (idxdb->mappedlen - idxdb->strend < keyl) {
	if (addstringpage(idxdb))
	    return RPMRC_FAIL;
    }
    memcpy(idxdb->mapped + idxdb->strend, key, keyl);
    *stroffp = idxdb->strend - idxdb->strstart;
    idxdb->strend += keyl;
    updateStrend(idxdb);
    return RPMRC_OK;
}

static inline void updatenew(rpmidxdb idxdb, unsigned int keyh, unsigned int newx, unsigned int x1, unsigned int x2)
{
    unsigned int h, hh = 7;
    unsigned char *ent;
    unsigned int hmask = idxdb->hmask;
    unsigned int x;
    
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = be2h(ent);
	if (x == 0)
	    break;
    }
    h2be(newx, ent);
    h2be(x1, ent + 4);
    if (x2 != -1)
        h2be(x1, ent + idxdb->nslots * 8);
}

static inline void updatekey(char *key, int keyl, rpmidxdb idxdb, unsigned int oldstroff, rpmidxdb nidxdb, unsigned int newstroff, unsigned char *done)
{
    unsigned int h, hh;
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask = idxdb->hmask;

    oldstroff |= keyh & idxdb->xmask;
    for (h = keyh & hmask, hh = 7; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	unsigned int x = be2h(ent);
	if (x == 0)
	    break;
	if (x != oldstroff)
	    continue;
	x = be2h(ent + 4);
	updatenew(nidxdb, keyh, newstroff | (keyh & nidxdb->xmask), x, (x & 0x80000000) ? be2h(ent + idxdb->nslots * 8) : -1);
	done[h >> 3] |= 1 << (h & 7);
    }
}

static int rpmidxRebuildInternal(rpmidxdb idxdb)
{
    struct rpmidxdb_s nidxdb_s, *nidxdb;
    char *tmpname;
    unsigned int i, nslots, maxstrsize, slotsize;
    unsigned int strend, stroff, xmask;
    unsigned char *done;
    unsigned char *ent;

    nidxdb = &nidxdb_s;
    memset(nidxdb, 0, sizeof(*nidxdb));
    tmpname = malloc(strlen(idxdb->filename) + 8);
    if (!tmpname)
	return RPMRC_FAIL;
    sprintf(tmpname, "%s-XXXXXX", idxdb->filename);
    nidxdb->fd = mkstemp(tmpname);
    if (nidxdb->fd == -1)
	return RPMRC_FAIL;

    /* don't trust usedslots and dummyslots */
    nslots = 0;
    for (i = 0, ent = idxdb->mapped + idxdb->slotstart; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = be2h(ent);
	if (x != 0 && x != -1)
	    nslots++;
    }
    if (nslots == 0)
	nslots = 256;
    while (nslots & (nslots - 1))
	nslots = nslots & (nslots - 1);
    nslots *= 4;
    nidxdb->nslots = nslots;
    nidxdb->hmask = nslots - 1;
    nidxdb->pagesize = sysconf(_SC_PAGE_SIZE);
    nidxdb->slotstart = nidxdb->pagesize;
    slotsize = (nslots * 12 + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    maxstrsize = (idxdb->strend - idxdb->strstart + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    if (maxstrsize < nidxdb->pagesize)
	maxstrsize = nidxdb->pagesize;
    nidxdb->mappedlen = nidxdb->pagesize + slotsize + maxstrsize;
    for (xmask = 0x00010000; xmask < maxstrsize + 2 * nidxdb->pagesize; xmask <<= 1)
      ;
    xmask = ~(xmask - 1);
    nidxdb->xmask = xmask;
    nidxdb->strstart = nidxdb->slotstart + slotsize;
    strend = nidxdb->strstart + 1;
    if (ftruncate(nidxdb->fd, nidxdb->mappedlen)) {
	close(nidxdb->fd);
	unlink(tmpname);
	return RPMRC_FAIL;
    }
    nidxdb->mapped = mmap(0, nidxdb->mappedlen, PROT_READ | PROT_WRITE, MAP_SHARED, nidxdb->fd, 0);
    if (nidxdb->mapped == MAP_FAILED) {
	close(nidxdb->fd);
	unlink(tmpname);
	return RPMRC_FAIL;
    }
    done = calloc(idxdb->nslots / 8 + 1, 1);
    if (!done) {
	munmap(nidxdb->mapped, nidxdb->mappedlen);
	close(nidxdb->fd);
	unlink(tmpname);
	return RPMRC_FAIL;
    }
    for (i = 0, ent = idxdb->mapped + idxdb->slotstart; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = be2h(ent);
	char *key;
        int keyl;

	if (x == 0 || x == -1)
	    continue;
	if (done[i >> 3] & (1 << (i & 7))) {
	    continue;
	}
	x &= ~idxdb->xmask;
	key = (char *)(idxdb->mapped + idxdb->strstart + x);
	keyl = strlen(key);
	stroff = strend - nidxdb->strstart;
	memcpy(nidxdb->mapped + strend, key, keyl + 1);
	strend += keyl + 1;
	updatekey(key, keyl, idxdb, x, nidxdb, stroff, done);
    }
    free(done);
    nidxdb->strend = strend;
    rpmidxWriteheader(nidxdb);
    munmap(nidxdb->mapped, nidxdb->mappedlen);
    strend = (strend + 2 * nidxdb->pagesize) & ~(nidxdb->pagesize - 1);
    ftruncate(nidxdb->fd, strend);
    if (rename(tmpname, idxdb->filename)) {
	close(nidxdb->fd);
	unlink(idxdb->filename);
	return RPMRC_FAIL;
    }
    if (idxdb->mapped)
        munmap(idxdb->mapped, idxdb->mappedlen);
    idxdb->mapped = 0;
    idxdb->mappedlen = 0;
    idxdb->fd = nidxdb->fd;
    if (rpmidxReadheader(idxdb))
	return RPMRC_FAIL;
    return RPMRC_OK;
}

static int rpmidxCheck(rpmidxdb idxdb)
{
    if (idxdb->usedslots * 2 > idxdb->nslots ||
	(idxdb->strexcess > 4096 && idxdb->strexcess * 4 > idxdb->strend - idxdb->strstart) ||
	(idxdb->strend - idxdb->strstart) >= ~idxdb->xmask) {
	if (rpmidxRebuildInternal(idxdb))
	    return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static int rpmidxPutInternal(rpmidxdb idxdb, unsigned int pkgidx, char *key, unsigned int keyidx)
{
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int stroff = 0;
    unsigned int freeh = -1;
    unsigned int x, h, hh = 7;
    unsigned int hmask;
    unsigned int xmask;
    unsigned char *ent;
    unsigned int x1, x2;

    if (pkgidx < 0x100000 && keyidx < 0x400) {
	x1 = pkgidx | keyidx << 20;
	x2 = -1;
    } else if (pkgidx < 0x1000000 && keyidx < 0x40) {
	x1 = pkgidx | keyidx << 24 | 0x40000000;
	x2 = -1;
    } else {
	x1 = keyidx | 0x80000000;
	x2 = pkgidx;
    }

    rpmidxCheck(idxdb);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = be2h(ent);
	if (x == 0)
	    break;
	if (x == -1) {
	    freeh = h;
	    continue;
	}
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!stroff) {
	    int r = equalstring(idxdb, x, key, keyl);
	    if (r == 0)
		continue;
	    if (r < 0)
		    return RPMRC_FAIL;
	    stroff = x;
	}
	if (stroff != x)
	    continue;
	/* string matches, check the pkgidx */
	if (be2h(ent + 4) == x1) {
	    if (x2 == -1 || be2h(ent + idxdb->nslots * 8) == x2)
		return RPMRC_OK;
	}
	/* other entry */
    }
    if (!stroff) {
	if (addnewstring(idxdb, key, keyl, &stroff)) {
	    return RPMRC_FAIL;
	}
	/* addnewstring may have changed the mapping! */
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
    }
    if (freeh == -1) {
	idxdb->usedslots++;
	updateUsedslots(idxdb);
    } else {
	ent = idxdb->mapped + idxdb->slotstart + 8 * freeh;
    }
    h2be(stroff | (keyh & xmask), ent);
    h2be(x1, ent + 4);
    if (x2 != -1)
	h2be(x2, ent + idxdb->nslots * 8);
    return RPMRC_OK;
}

static int rpmidxEraseInternal(rpmidxdb idxdb, unsigned int pkgidx, char *key, unsigned int keyidx)
{
    unsigned int stroff = 0;
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask;
    unsigned int xmask;
    unsigned int x, h, hh = 7;
    int otherusers = 0;
    unsigned int x1, x2;

    if (pkgidx < 0x100000 && keyidx < 0x400) {
	x1 = pkgidx | keyidx << 20;
	x2 = -1;
    } else if (pkgidx < 0x1000000 && keyidx < 0x40) {
	x1 = pkgidx | keyidx << 24 | 0x40000000;
	x2 = -1;
    } else {
	x1 = keyidx | 0x80000000;
	x2 = pkgidx;
    }

    rpmidxCheck(idxdb);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = be2h(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!stroff) {
	    int r = equalstring(idxdb, x, key, keyl);
	    if (r == 0)
		continue;
	    if (r < 0)
		    return RPMRC_FAIL;
	    stroff = x;
	}
	if (stroff != x)
	    continue;
	/* string matches, check the pkgidx */
	if (be2h(ent + 4) != x1) {
	    otherusers = 1;
	    continue;
	}
	if (x2 != -1 && be2h(ent + idxdb->nslots * 8) != x2) {
	    otherusers = 1;
	    continue;
	}
	memset(ent, 255, 8);
	if (x2 != -1)
	    memset(ent + idxdb->nslots * 8, 255, 4);
	idxdb->dummyslots++;
	updateDummyslots(idxdb);
	/* we continue searching to see if someone else uses the string */
    }
    if (stroff && !otherusers) {
	/* zero out unused string */
	memset(idxdb->mapped + idxdb->strstart + stroff, 0, keyl);
	idxdb->strexcess += keyl + 1;
	updateStrexcess(idxdb);
    }
    return RPMRC_OK;
}

static int rpmidxGetInternal(rpmidxdb idxdb, char *key, unsigned int **pkgidxlistp, unsigned int *pkgidxnump)
{
    unsigned int stroff = 0;
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask = idxdb->hmask;
    unsigned int xmask = idxdb->xmask;
    unsigned int x, xidx, h, hh = 7;
    unsigned int nhits = 0;
    unsigned int *hits = 0;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = be2h(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!stroff) {
	    int r = equalstring(idxdb, x, key, keyl);
	    if (r == 0)
		continue;
	    if (r < 0)
		    return RPMRC_FAIL;
	    stroff = x;
	}
	if (stroff != x)
	    continue;
	if ((nhits & 15) == 0) {
	    if (!hits) {
		hits = malloc(16 * sizeof(unsigned int));
	    } else {
		hits = realloc(hits, (nhits + 16) * sizeof(unsigned int));
	    }
	    if (!hits)
		return RPMRC_FAIL;
	}
	x = be2h(ent + 4);
	if (x & 0x80000000) {
	  /* overflow */
	  xidx = x ^ 0x80000000;
	  x = be2h(ent + 8 * idxdb->nslots);
	} else if (x & 0x40000000) {
	  xidx = (x ^ 0x40000000) >> 24;
	  x &= 0xffffff;
	} else {
	  xidx = x >> 20;
	  x &= 0xfffff;
	}
	hits[nhits++] = x;
	hits[nhits++] = xidx;
    }
    *pkgidxlistp = hits;
    *pkgidxnump = nhits;
    return RPMRC_OK;
}

static int rpmidxListInternal(rpmidxdb idxdb, char ***keylistp, unsigned int *nkeylistp)
{
    char **keylist = 0;
    int nkeylist = 0;
    unsigned int soff;
    keylist = malloc(16 * sizeof(char *));
    if (!keylist)
	return RPMRC_FAIL;
    for (soff = idxdb->strstart + 1; soff < idxdb->strend; soff++) {
	char *key = (char *)idxdb->mapped + soff;
	if (!*key)
	    continue;
	if ((nkeylist & 15) == 0) {
	    char **kl = realloc(keylist, (nkeylist + 16) * sizeof(char *));
	    if (!kl) {
		int i;
		for (i = 0; i < nkeylist; i++)
		    free(keylist[i]);
		free(keylist);
		return RPMRC_FAIL;
	    }
	    keylist = kl;
	}
	keylist[nkeylist] = strdup(key);
	if (!keylist[nkeylist]) {
	    int i;
	    for (i = 0; i < nkeylist; i++)
		free(keylist[i]);
	    free(keylist);
	    return RPMRC_FAIL;
	}
	nkeylist++;
	soff += strlen(key);
    }
    *keylistp = keylist;
    *nkeylistp = nkeylist;
    return RPMRC_OK;
}


static int rpmidxInitInternal(rpmidxdb idxdb)
{
    struct stat stb; 
    if (fstat(idxdb->fd, &stb)) {
	return RPMRC_FAIL;
    }    
    if (stb.st_size) {
	return RPMRC_OK;	/* somebody else was faster */
    }
    return rpmidxRebuildInternal(idxdb);
}

static int rpmidxInit(rpmidxdb idxdb)
{
    int rc;
    if (rpmpkgLock(idxdb->pkgdb, 1))
	return RPMRC_FAIL;
    rc = rpmidxInitInternal(idxdb);
    rpmpkgUnlock(idxdb->pkgdb, 1);
    return rc;
}

int rpmidxOpen(rpmidxdb *idxdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode)
{
    struct stat stb;
    rpmidxdb idxdb;

    *idxdbp = 0;
    idxdb = calloc(1, sizeof(*idxdb));
    idxdb->filename = strdup(filename);
    if (!idxdb->filename) {
        free(idxdb);
        return RPMRC_FAIL;
    }   
    if ((idxdb->fd = open(filename, flags, mode)) == -1) {
        return RPMRC_FAIL;
    }   
    if (fstat(idxdb->fd, &stb)) {
        close(idxdb->fd);
        free(idxdb);
        return RPMRC_FAIL;
    }   
    idxdb->pkgdb = pkgdb;
    idxdb->flags = flags;
    idxdb->mode = mode;
    idxdb->pagesize = sysconf(_SC_PAGE_SIZE);
    if (stb.st_size == 0) {
        if (rpmidxInit(idxdb)) {
            close(idxdb->fd);
            free(idxdb);
            return RPMRC_FAIL;
        }
    }   
    *idxdbp = idxdb;
    return RPMRC_OK;
}

void rpmidxClose(rpmidxdb idxdb)
{
    if (idxdb->mapped) {
	munmap(idxdb->mapped, idxdb->mappedlen);
	idxdb->mapped = 0;
	idxdb->mappedlen = 0;
    }
    if (idxdb->fd >= 0) {
        close(idxdb->fd);
        idxdb->fd = -1; 
    }   
}
int rpmidxPut(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys)
{
    unsigned int i;
    if (!pkgidx) {
        return RPMRC_FAIL;
    }
    if (rpmpkgLock(idxdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmidxReadheader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    for (i = 0; i < nkeys; i++) {
	rpmidxPutInternal(idxdb, pkgidx, keys[i], i);
    }
    rpmpkgUnlock(idxdb->pkgdb, 1);
    return RPMRC_OK;
}

int rpmidxErase(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys)
{
    unsigned int i;
    if (!pkgidx) {
        return RPMRC_FAIL;
    }
    if (rpmpkgLock(idxdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmidxReadheader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    for (i = 0; i < nkeys; i++) {
	rpmidxEraseInternal(idxdb, pkgidx, keys[i], i);
    }
    rpmpkgUnlock(idxdb->pkgdb, 1);
    return RPMRC_OK;
}

int rpmidxGet(rpmidxdb idxdb, char *key, unsigned int **pkgidxlistp, unsigned int *pkgidxnump)
{
    int rc;
    *pkgidxlistp = 0;
    *pkgidxnump = 0;
    if (rpmpkgLock(idxdb->pkgdb, 0))
	return RPMRC_FAIL;
    if (rpmidxReadheader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    rc = rpmidxGetInternal(idxdb, key, pkgidxlistp, pkgidxnump);
    rpmpkgUnlock(idxdb->pkgdb, 0);
    return rc;
}

int rpmidxList(rpmidxdb idxdb, char ***keylistp, unsigned int *nkeylistp)
{
    int rc;
    *keylistp = 0;
    *nkeylistp = 0;
    if (rpmpkgLock(idxdb->pkgdb, 0))
	return RPMRC_FAIL;
    if (rpmidxReadheader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    rc = rpmidxListInternal(idxdb, keylistp, nkeylistp);
    rpmpkgUnlock(idxdb->pkgdb, 0);
    return rc;
}
