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

#include <endian.h>

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

    unsigned int keystart;
    unsigned int keyend;
    unsigned int keyexcess;

    unsigned int hmask;
    unsigned int xmask;
} * rpmidxdb;

static inline unsigned int le2h(unsigned char *p) 
{
    return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline void h2le(unsigned int x, unsigned char *p) 
{
    p[0] = x;
    p[1] = x >> 8; 
    p[2] = x >> 16;
    p[3] = x >> 24;
}

/* aligned versions */
static inline unsigned int le2ha(unsigned char *p) 
{
    unsigned int x = *(unsigned int *)p;
    return le32toh(x);
}

static inline void h2lea(unsigned int x, unsigned char *p) 
{
    *(unsigned int *)p = htole32(x);
}

/*** Header management ***/

#define IDXDB_MAGIC     ('R' << 24 | 'p' << 16 | 'm' << 8 | 'I')

/* header
 * generation
 * nslots
 * usedslots
 * dummyslots
 * xmask
 * keystart
 * keyend
 * keyexcess
 */

static int rpmidxReadHeader(rpmidxdb idxdb)
{
    struct stat stb;

    if (idxdb->mapped) {
	if (le2ha(idxdb->mapped + 4) == idxdb->generation) {
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
    if (le2ha(idxdb->mapped) != IDXDB_MAGIC) {
	munmap(idxdb->mapped, stb.st_size);
	idxdb->mapped = 0;
	return RPMRC_FAIL;
    }
    idxdb->mappedlen = stb.st_size;

    idxdb->generation = le2ha(idxdb->mapped + 4);
    idxdb->slotstart  = le2ha(idxdb->mapped + 8);
    idxdb->nslots     = le2ha(idxdb->mapped + 12);
    idxdb->usedslots  = le2ha(idxdb->mapped + 16);
    idxdb->dummyslots = le2ha(idxdb->mapped + 20);
    idxdb->xmask      = le2ha(idxdb->mapped + 24);
    idxdb->keystart   = le2ha(idxdb->mapped + 28);
    idxdb->keyend     = le2ha(idxdb->mapped + 32);
    idxdb->keyexcess  = le2ha(idxdb->mapped + 36);

    idxdb->hmask = idxdb->nslots - 1;
    return RPMRC_OK;
}

static int rpmidxWriteHeader(rpmidxdb idxdb)
{
    if (!idxdb->mapped)
	return RPMRC_FAIL;
    h2lea(IDXDB_MAGIC,       idxdb->mapped);
    h2lea(idxdb->generation, idxdb->mapped + 4);
    h2lea(idxdb->slotstart,  idxdb->mapped + 8);
    h2lea(idxdb->nslots,     idxdb->mapped + 12);
    h2lea(idxdb->usedslots,  idxdb->mapped + 16);
    h2lea(idxdb->dummyslots, idxdb->mapped + 20);
    h2lea(idxdb->xmask,      idxdb->mapped + 24);
    h2lea(idxdb->keystart,   idxdb->mapped + 28);
    h2lea(idxdb->keyend,     idxdb->mapped + 32);
    h2lea(idxdb->keyexcess,  idxdb->mapped + 36);
    return RPMRC_OK;
}

static inline void updateGeneration(rpmidxdb idxdb)
{
   h2lea(idxdb->generation, idxdb->mapped + 4);
}

static inline void updateKeyend(rpmidxdb idxdb)
{
   h2lea(idxdb->keyend, idxdb->mapped + 32);
}

static inline void updateKeyexcess(rpmidxdb idxdb)
{
   h2lea(idxdb->keyexcess, idxdb->mapped + 36);
}

static inline void updateUsedslots(rpmidxdb idxdb)
{
   h2lea(idxdb->usedslots, idxdb->mapped + 16);
}

static inline void updateDummyslots(rpmidxdb idxdb)
{
   h2lea(idxdb->dummyslots, idxdb->mapped + 20);
}



/*** Key management ***/

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

static inline int equalkey(rpmidxdb idxdb, unsigned int off, char *key, int keyl)
{
    keyl++;	/* include trailing 0 */
    if (idxdb->keystart + off + keyl > idxdb->keyend)
	return 0;
    if (memcmp(key, idxdb->mapped + idxdb->keystart + off, keyl))
	return 0;
    return 1;
}

static int createempty(rpmidxdb idxdb, off_t off, size_t size)
{
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    while (size >= 4096) {
	if (pwrite(idxdb->fd, buf, 4096, off) != 4096)
	    return RPMRC_FAIL;
	off += 4096;
	size -= 4096;
    }
    if (size > 0 && pwrite(idxdb->fd, buf, size , off) != size)
	return RPMRC_FAIL;
    return RPMRC_OK;
}

static int addkeypage(rpmidxdb idxdb) {
    unsigned char *newaddr;

    /* we don't use ftruncate because we want to create a "backed" page */
    if (createempty(idxdb, idxdb->mappedlen, idxdb->pagesize))
	return RPMRC_FAIL;
    newaddr = mremap(idxdb->mapped, idxdb->mappedlen, idxdb->mappedlen + idxdb->pagesize, MREMAP_MAYMOVE);
    if (newaddr == MAP_FAILED)
	return RPMRC_FAIL;
    idxdb->mapped = newaddr;
    idxdb->mappedlen += idxdb->pagesize;
    return RPMRC_OK;
}

static int addnewkey(rpmidxdb idxdb, char *key, int keyl, unsigned int *keyoffp)
{
    if (!keyl) {
	/* special case empty string, it is always at offset 1 */
	/* we use idxdb->mapped[idxdb->keystart] to flag if the key is "in use" */
	*keyoffp = 1;
	idxdb->mapped[idxdb->keystart] = 0;
	return RPMRC_OK;
    }
    keyl++;	/* include trailing 0 */
    while (idxdb->mappedlen - idxdb->keyend < keyl) {
	if (addkeypage(idxdb))
	    return RPMRC_FAIL;
    }
    memcpy(idxdb->mapped + idxdb->keyend, key, keyl);
    *keyoffp = idxdb->keyend - idxdb->keystart;
    idxdb->keyend += keyl;
    updateKeyend(idxdb);
    return RPMRC_OK;
}


/*** Data encoding/decoding ***/

/* Encode a (pkgidx, datidx) tuple into a (data, ovldata) tuple in a way
 * that most of the time ovldata will be zero. */
static inline unsigned int encodedata(rpmidxdb idxdb, unsigned int pkgidx, unsigned int datidx, unsigned int *ovldatap)
{
    if (pkgidx < 0x100000 && datidx < 0x400) {
	*ovldatap = 0;
	return pkgidx | datidx << 20;
    } else if (pkgidx < 0x1000000 && datidx < 0x40) {
	*ovldatap = 0;
	return pkgidx | datidx << 24 | 0x40000000;
    } else {
	*ovldatap = pkgidx;
	return datidx | 0x80000000;
    }
}

/* Decode (data, ovldata) back into (pkgidx, datidx) */
static inline unsigned int decodedata(rpmidxdb idxdb, unsigned int data, unsigned int ovldata, unsigned int *datidxp)
{
    if (data & 0x80000000) {
	*datidxp = data ^ 0x80000000;
	return ovldata;
    } else if (data & 0x40000000) {
        *datidxp = (data ^ 0x40000000) >> 24;
	return data & 0xffffff;
    } else {
        *datidxp = data >> 20;
	return data & 0xfffff;
    }
}


/*** Rebuild helpers ***/

/* copy a single data entry into the new database */
static inline void updatenew(rpmidxdb idxdb, unsigned int keyh, unsigned int newx, unsigned int data, unsigned int ovldata)
{
    unsigned int h, hh = 7;
    unsigned char *ent;
    unsigned int hmask = idxdb->hmask;
    unsigned int x;
    
    /* find an empty slot */
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
    }
    /* write data */
    h2lea(newx, ent);
    h2lea(data, ent + 4);
    if (ovldata)
        h2lea(ovldata, ent + idxdb->nslots * 8);
    idxdb->usedslots++;
}

/* copy all entries belonging to a single key from the old database into the new database */
static inline void updatekey(char *key, int keyl, rpmidxdb idxdb, unsigned int oldkeyoff, rpmidxdb nidxdb, unsigned int newkeyoff, unsigned char *done)
{
    unsigned int h, hh;
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask = idxdb->hmask;

    oldkeyoff |= keyh & idxdb->xmask;
    newkeyoff |= keyh & nidxdb->xmask;
    for (h = keyh & hmask, hh = 7; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	unsigned int data, ovldata;
	unsigned int x = le2ha(ent);
	if (x == 0)
	    break;
	if (x != oldkeyoff)
	    continue;
	data = le2ha(ent + 4);
	ovldata = (data & 0x80000000) ? le2ha(ent + idxdb->nslots * 8) : 0;
	updatenew(nidxdb, keyh, newkeyoff, data, ovldata);
	done[h >> 3] |= 1 << (h & 7);
    }
}

static int rpmidxRebuildInternal(rpmidxdb idxdb)
{
    struct rpmidxdb_s nidxdb_s, *nidxdb;
    char *tmpname;
    unsigned int i, nslots, maxkeysize, slotsize;
    unsigned int keyend, keyoff, xmask;
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
	unsigned int x = le2ha(ent);
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
    maxkeysize = (idxdb->keyend - idxdb->keystart + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    if (maxkeysize < nidxdb->pagesize)
	maxkeysize = nidxdb->pagesize;
    nidxdb->mappedlen = nidxdb->pagesize + slotsize + maxkeysize;
    for (xmask = 0x00010000; xmask < maxkeysize + 2 * nidxdb->pagesize; xmask <<= 1)
      ;
    xmask = ~(xmask - 1);
    nidxdb->xmask = xmask;
    nidxdb->keystart = nidxdb->slotstart + slotsize;
    keyend = nidxdb->keystart + 1 + 1;
    if (createempty(nidxdb, 0, nidxdb->mappedlen)) {
	close(nidxdb->fd);
	unlink(tmpname);
	free(tmpname);
	return RPMRC_FAIL;
    }
    nidxdb->mapped = mmap(0, nidxdb->mappedlen, PROT_READ | PROT_WRITE, MAP_SHARED, nidxdb->fd, 0);
    if (nidxdb->mapped == MAP_FAILED) {
	close(nidxdb->fd);
	unlink(tmpname);
	free(tmpname);
	return RPMRC_FAIL;
    }
    nidxdb->mapped[nidxdb->keystart] = 255;	/* empty string not yet in use */
    done = calloc(idxdb->nslots / 8 + 1, 1);
    if (!done) {
	munmap(nidxdb->mapped, nidxdb->mappedlen);
	close(nidxdb->fd);
	unlink(tmpname);
	free(tmpname);
	return RPMRC_FAIL;
    }
    for (i = 0, ent = idxdb->mapped + idxdb->slotstart; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = le2ha(ent);
	char *key;
        int keyl;

	if (x == 0 || x == -1)
	    continue;
	if (done[i >> 3] & (1 << (i & 7))) {
	    continue;	/* we already did that one */
	}
	x &= ~idxdb->xmask;
	key = (char *)(idxdb->mapped + idxdb->keystart + x);
	keyl = strlen(key);
	if (!keyl) {
	    /* special case empty string, see addnewkey() */
	    keyoff = 1;
	    nidxdb->mapped[nidxdb->keystart] = 0;
	} else {
	    keyoff = keyend - nidxdb->keystart;
	    memcpy(nidxdb->mapped + keyend, key, keyl + 1);
	    keyend += keyl + 1;
	}
	updatekey(key, keyl, idxdb, x, nidxdb, keyoff, done);
    }
    free(done);
    nidxdb->keyend = keyend;
    rpmidxWriteHeader(nidxdb);
    munmap(nidxdb->mapped, nidxdb->mappedlen);
    keyend = (keyend + 2 * nidxdb->pagesize) & ~(nidxdb->pagesize - 1);
    ftruncate(nidxdb->fd, keyend);
    if (rename(tmpname, idxdb->filename)) {
	close(nidxdb->fd);
	unlink(tmpname);
	free(tmpname);
	return RPMRC_FAIL;
    }
    free(tmpname);
    if (idxdb->mapped)
        munmap(idxdb->mapped, idxdb->mappedlen);
    idxdb->mapped = 0;
    idxdb->mappedlen = 0;
    idxdb->fd = nidxdb->fd;
    if (rpmidxReadHeader(idxdb))
	return RPMRC_FAIL;
    return RPMRC_OK;
}

/* check if we need to rebuild the index */
static int rpmidxCheck(rpmidxdb idxdb)
{
    if (idxdb->usedslots * 2 > idxdb->nslots ||
	(idxdb->keyexcess > 4096 && idxdb->keyexcess * 4 > idxdb->keyend - idxdb->keystart) ||
	(idxdb->keyend - idxdb->keystart) >= ~idxdb->xmask) {
	if (rpmidxRebuildInternal(idxdb))
	    return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static int rpmidxPutInternal(rpmidxdb idxdb, unsigned int pkgidx, char *key, unsigned int datidx)
{
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int keyoff = 0;
    unsigned int freeh = -1;
    unsigned int x, h, hh = 7;
    unsigned int hmask;
    unsigned int xmask;
    unsigned char *ent;
    unsigned int data, ovldata;

    if (datidx >= 0x80000000)
	return RPMRC_FAIL;
    rpmidxCheck(idxdb);
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
	if (x == -1) {
	    freeh = h;
	    continue;
	}
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!keyoff) {
	    if (!equalkey(idxdb, x, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
	    continue;
	/* string matches, check data/ovldata */
	if (le2ha(ent + 4) == data) {
	    if (!ovldata || le2ha(ent + idxdb->nslots * 8) == ovldata)
		return RPMRC_OK;	/* already in database */
	}
	/* continue searching */
    }
    if (!keyoff) {
	if (addnewkey(idxdb, key, keyl, &keyoff)) {
	    return RPMRC_FAIL;
	}
	/* re-calculate ent, addnewkey may have changed the mapping! */
	ent = idxdb->mapped + idxdb->slotstart + 8 * h;
    }
    if (freeh == -1) {
	idxdb->usedslots++;
	updateUsedslots(idxdb);
    } else {
	ent = idxdb->mapped + idxdb->slotstart + 8 * freeh;
    }
    keyoff |= keyh & xmask;
    h2lea(keyoff, ent);
    h2lea(data, ent + 4);
    if (ovldata)
	h2lea(ovldata, ent + idxdb->nslots * 8);
    return RPMRC_OK;
}

static int rpmidxEraseInternal(rpmidxdb idxdb, unsigned int pkgidx, char *key, unsigned int datidx)
{
    unsigned int keyoff = 0;
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask;
    unsigned int xmask;
    unsigned int x, h, hh = 7;
    int otherusers = 0;
    unsigned int data, ovldata;

    if (datidx >= 0x80000000)
	return RPMRC_FAIL;
    rpmidxCheck(idxdb);
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!keyoff) {
	    if (!equalkey(idxdb, x, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
	    continue;
	/* string matches, check data/ovldata */
	if (le2ha(ent + 4) != data) {
	    otherusers = 1;
	    continue;
	}
	if (ovldata && le2ha(ent + idxdb->nslots * 8) != ovldata) {
	    otherusers = 1;
	    continue;
	}
	/* convert entry to a dummy slot */
	h2lea(-1, ent);
	h2lea(-1, ent + 4);
	if (ovldata)
	    h2lea(0, ent + idxdb->nslots * 8);
	idxdb->dummyslots++;
	updateDummyslots(idxdb);
	/* continue searching */
    }
    if (keyoff && !otherusers) {
	if (!keyl) {
	    /* special case empty string, see addnewkey() */
	    idxdb->mapped[idxdb->keystart] = 255;
	} else {
	    /* zero out unused key so that rpmidxList no longer returns it */
	    memset(idxdb->mapped + idxdb->keystart + keyoff, 0, keyl);
	    idxdb->keyexcess += keyl + 1;
	    updateKeyexcess(idxdb);
	}
    }
    return RPMRC_OK;
}

static int rpmidxGetInternal(rpmidxdb idxdb, char *key, unsigned int **pkgidxlistp, unsigned int *pkgidxnump)
{
    unsigned int keyoff = 0;
    int keyl = strlen(key);
    unsigned int keyh = murmurhash((unsigned char *)key, (unsigned int)keyl);
    unsigned int hmask = idxdb->hmask;
    unsigned int xmask = idxdb->xmask;
    unsigned int x, h, hh = 7;
    unsigned int data, ovldata, datidx;
    unsigned int nhits = 0;
    unsigned int *hits = 0;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->mapped + idxdb->slotstart + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (((x ^ keyh) & xmask) != 0)
	    continue;
	x &= ~xmask;
	if (!keyoff) {
	    if (!equalkey(idxdb, x, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
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
	data = le2ha(ent + 4);
	ovldata = (data & 0x80000000) ? le2ha(ent + idxdb->nslots * 8) : 0;
	hits[nhits++] = decodedata(idxdb, data, ovldata, &datidx);
	hits[nhits++] = datidx;
    }
    *pkgidxlistp = hits;
    *pkgidxnump = nhits;
    return RPMRC_OK;
}

static int rpmidxListInternal(rpmidxdb idxdb, char ***keylistp, unsigned int *nkeylistp)
{
    char **keylist = 0;
    int nkeylist = 0;
    unsigned int koff;
    keylist = malloc(16 * sizeof(char *));
    if (!keylist)
	return RPMRC_FAIL;
    
    /* special case empty string, see addnewkey() */
    if (!idxdb->mapped[idxdb->keystart]) {
	/* empty string in use */
	keylist[0] = strdup("");
	if (!keylist[0]) {
	    free(keylist);
	    return RPMRC_FAIL;
	}
	nkeylist++;
    }
    for (koff = idxdb->keystart + 2; koff < idxdb->keyend; koff++) {
	char *key = (char *)idxdb->mapped + koff;
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
	koff += strlen(key);
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
    free(idxdb->filename);
    free(idxdb);
}
int rpmidxPut(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys)
{
    unsigned int i;
    if (!pkgidx) {
        return RPMRC_FAIL;
    }
    if (rpmpkgLock(idxdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmidxReadHeader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    for (i = 0; i < nkeys; i++) {
	if (!keys[i])
	    continue;
	if (rpmidxPutInternal(idxdb, pkgidx, keys[i], i)) {
	    rpmpkgUnlock(idxdb->pkgdb, 1);
	    return RPMRC_FAIL;
	}
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
    if (rpmidxReadHeader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    for (i = 0; i < nkeys; i++) {
	if (!keys[i])
	    continue;
	if (rpmidxEraseInternal(idxdb, pkgidx, keys[i], i)) {
	    rpmpkgUnlock(idxdb->pkgdb, 1);
	    return RPMRC_FAIL;
	}
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
    if (rpmidxReadHeader(idxdb)) {
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
    if (rpmidxReadHeader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    rc = rpmidxListInternal(idxdb, keylistp, nkeylistp);
    rpmpkgUnlock(idxdb->pkgdb, 0);
    return rc;
}

int rpmidxUpdateGeneration(rpmidxdb idxdb)
{
    unsigned int generation;
    if (rpmpkgLock(idxdb->pkgdb, 1))
	return RPMRC_FAIL;
    if (rpmidxReadHeader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    if (rpmpkgGetIdxGeneration(idxdb->pkgdb, &generation)) {
	rpmpkgUnlock(idxdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    if (idxdb->generation != generation) {
	idxdb->generation = generation;
	updateGeneration(idxdb);
    }
    rpmpkgUnlock(idxdb->pkgdb, 1);
    return RPMRC_OK;
}

int rpmidxStats(rpmidxdb idxdb)
{
    if (rpmpkgLock(idxdb->pkgdb, 0))
	return RPMRC_FAIL;
    if (rpmidxReadHeader(idxdb)) {
	rpmpkgUnlock(idxdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    printf("--- IndexDB Stats\n");
    printf("Filename: %s\n", idxdb->filename);
    printf("Generation: %u\n", idxdb->generation);
    printf("Slots: %u\n", idxdb->nslots);
    printf("Used slots: %u\n", idxdb->usedslots);
    printf("Dummy slots: %u\n", idxdb->dummyslots);
    printf("Key data size: %u\n", idxdb->keyend - idxdb->keystart);
    printf("Key excess: %u\n", idxdb->keyexcess);
    printf("XMask : 0x%08x\n", idxdb->xmask);
    rpmpkgUnlock(idxdb->pkgdb, 1);
    return RPMRC_OK;
}
