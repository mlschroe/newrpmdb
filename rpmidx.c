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
#include "rpmxdb.h"

#define RPMRC_FAIL 1
#define RPMRC_OK 0

typedef struct rpmidxdb_s {
    rpmpkgdb pkgdb;		/* master database */

    char *filename;
    int fd;                     /* our file descriptor */
    int flags;
    int mode;

    rpmxdb xdb;
    unsigned int xdbtag;
    unsigned int xdbid_headslot;
    unsigned int xdbid_str;

    unsigned int pagesize;

    unsigned char *head_mapped;
    unsigned int   head_mappedlen;
    unsigned char *slot_mapped;
    unsigned int   slot_mappedlen;
    unsigned char *str_mapped;
    unsigned int   str_mappedlen;

    unsigned int generation;
    unsigned int slotoffset;
    unsigned int nslots;
    unsigned int usedslots;
    unsigned int dummyslots;

    unsigned int keyoffset;
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

#define IDXDB_MAGIC     ('R' | 'p' << 8 | 'm' << 16 | 'I' << 24)

/* header
 * generation
 * nslots
 * usedslots
 * dummyslots
 * xmask
 * keyoffset
 * keyend
 * keyexcess
 */

static void headslotmapcb(rpmxdb xdb, void *data, void *newaddr, size_t newsize) {
    rpmidxdb idxdb = data;
    if (!newaddr) {
	idxdb->head_mapped = idxdb->slot_mapped = 0;
	idxdb->head_mappedlen = idxdb->slot_mappedlen = 0;
    } else {
	idxdb->head_mapped = newaddr;
	idxdb->head_mappedlen = idxdb->pagesize;
	idxdb->slot_mapped = newaddr + idxdb->pagesize;
	idxdb->slot_mappedlen = newsize - idxdb->pagesize;
    }
}

static void keymapcb(rpmxdb xdb, void *data, void *newaddr, size_t newsize) {
    rpmidxdb idxdb = data;
    idxdb->str_mapped = newaddr;
    idxdb->str_mappedlen = newsize;
}

static int rpmidxMap(rpmidxdb idxdb)
{
    struct stat stb;
    if (idxdb->xdb) {
	if (rpmxdbMapBlob(idxdb->xdb, idxdb->xdbid_headslot, headslotmapcb, idxdb)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbMapBlob(idxdb->xdb, idxdb->xdbid_str, keymapcb, idxdb)) {
	    rpmxdbUnmapBlob(idxdb->xdb, idxdb->xdbid_headslot);
	    return RPMRC_FAIL;
	}
    } else {
	if (fstat(idxdb->fd, &stb)) {
	    return RPMRC_FAIL;
	}
	if ((stb.st_size & (idxdb->pagesize - 1)) != 0) {
	    return RPMRC_FAIL;
	}
	if (stb.st_size < idxdb->pagesize * 3) {
	    return RPMRC_FAIL;
	}
	idxdb->head_mapped = mmap(0, stb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, idxdb->fd, 0);
	if (idxdb->head_mapped == MAP_FAILED) {
	    idxdb->head_mapped = 0;
	    return RPMRC_FAIL;
	}
	/* we don't yet noew how to distribut the mapping, so assign everything to head for now */
	idxdb->head_mappedlen = stb.st_size;
	idxdb->slot_mapped = idxdb->str_mapped = 0;
	idxdb->slot_mappedlen = idxdb->str_mappedlen = 0;
    }
    return RPMRC_OK;
}

static void rpmidxUnmap(rpmidxdb idxdb)
{
    if (!idxdb->head_mapped)
	return;
    if (idxdb->xdb) {
	rpmxdbUnmapBlob(idxdb->xdb, idxdb->xdbid_headslot);
	rpmxdbUnmapBlob(idxdb->xdb, idxdb->xdbid_str);
    } else {
	munmap(idxdb->head_mapped, idxdb->head_mappedlen + idxdb->slot_mappedlen + idxdb->str_mappedlen);
	idxdb->head_mapped = idxdb->slot_mapped = idxdb->str_mapped = 0;
	idxdb->head_mappedlen = idxdb->slot_mappedlen = idxdb->str_mappedlen = 0;
    }
}

static int rpmidxReadHeader(rpmidxdb idxdb)
{
    if (idxdb->head_mapped) {
	if (le2ha(idxdb->head_mapped + 4) == idxdb->generation) {
	    return RPMRC_OK;
	}
	rpmidxUnmap(idxdb);
    }
    if (rpmidxMap(idxdb))
	return RPMRC_FAIL;
    if (le2ha(idxdb->head_mapped) != IDXDB_MAGIC) {
	rpmidxUnmap(idxdb);
	return RPMRC_FAIL;
    }

    idxdb->generation = le2ha(idxdb->head_mapped + 4);
    idxdb->slotoffset = le2ha(idxdb->head_mapped + 8);
    idxdb->nslots     = le2ha(idxdb->head_mapped + 12);
    idxdb->usedslots  = le2ha(idxdb->head_mapped + 16);
    idxdb->dummyslots = le2ha(idxdb->head_mapped + 20);
    idxdb->xmask      = le2ha(idxdb->head_mapped + 24);
    idxdb->keyoffset  = le2ha(idxdb->head_mapped + 28);
    idxdb->keyend     = le2ha(idxdb->head_mapped + 32);
    idxdb->keyexcess  = le2ha(idxdb->head_mapped + 36);

    idxdb->hmask = idxdb->nslots - 1;

    if (!idxdb->slot_mapped) {
	/* fixup mapped */
	idxdb->slot_mapped = idxdb->head_mapped + idxdb->slotoffset;
	idxdb->str_mapped = idxdb->head_mapped + idxdb->keyoffset;
	idxdb->slot_mappedlen = idxdb->keyoffset - idxdb->pagesize;
	idxdb->str_mappedlen = idxdb->head_mappedlen - idxdb->keyoffset;
	idxdb->head_mappedlen = idxdb->pagesize;
    }

    return RPMRC_OK;
}

static int rpmidxWriteHeader(rpmidxdb idxdb)
{
    if (!idxdb->head_mapped)
	return RPMRC_FAIL;
    h2lea(IDXDB_MAGIC,       idxdb->head_mapped);
    h2lea(idxdb->generation, idxdb->head_mapped + 4);
    h2lea(idxdb->slotoffset, idxdb->head_mapped + 8);
    h2lea(idxdb->nslots,     idxdb->head_mapped + 12);
    h2lea(idxdb->usedslots,  idxdb->head_mapped + 16);
    h2lea(idxdb->dummyslots, idxdb->head_mapped + 20);
    h2lea(idxdb->xmask,      idxdb->head_mapped + 24);
    h2lea(idxdb->keyoffset,  idxdb->head_mapped + 28);
    h2lea(idxdb->keyend,     idxdb->head_mapped + 32);
    h2lea(idxdb->keyexcess,  idxdb->head_mapped + 36);
    return RPMRC_OK;
}

static inline void updateGeneration(rpmidxdb idxdb)
{
   h2lea(idxdb->generation, idxdb->head_mapped + 4);
}

static inline void updateUsedslots(rpmidxdb idxdb)
{
   h2lea(idxdb->usedslots, idxdb->head_mapped + 16);
}

static inline void updateDummyslots(rpmidxdb idxdb)
{
   h2lea(idxdb->dummyslots, idxdb->head_mapped + 20);
}

static inline void updateKeyend(rpmidxdb idxdb)
{
   h2lea(idxdb->keyend, idxdb->head_mapped + 32);
}

static inline void updateKeyexcess(rpmidxdb idxdb)
{
   h2lea(idxdb->keyexcess, idxdb->head_mapped + 36);
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
    if (off + keyl > idxdb->keyend)
	return 0;
    if (memcmp(key, idxdb->str_mapped + off, keyl))
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
    unsigned int oldmappedlen;

    if (idxdb->xdb) {
	if (rpmxdbResizeBlob(idxdb->xdb, idxdb->xdbid_str, idxdb->str_mappedlen + idxdb->pagesize))
	    return RPMRC_FAIL;
	return RPMRC_OK;
    }
    /* we don't use ftruncate because we want to create a "backed" page */
    oldmappedlen = idxdb->head_mappedlen + idxdb->slot_mappedlen + idxdb->str_mappedlen;
    if (createempty(idxdb, oldmappedlen, idxdb->pagesize))
	return RPMRC_FAIL;
    newaddr = mremap(idxdb->head_mapped, oldmappedlen, oldmappedlen + idxdb->pagesize, MREMAP_MAYMOVE);
    if (newaddr == MAP_FAILED)
	return RPMRC_FAIL;
    if (newaddr != idxdb->head_mapped) {
	idxdb->head_mapped = newaddr;
	idxdb->slot_mapped = idxdb->head_mapped + idxdb->head_mappedlen;
	idxdb->str_mapped = idxdb->slot_mapped + idxdb->slot_mappedlen;
    }
    idxdb->str_mappedlen += idxdb->pagesize;
    return RPMRC_OK;
}

static int addnewkey(rpmidxdb idxdb, char *key, int keyl, unsigned int *keyoffp)
{
    if (!keyl) {
	/* special case empty string, it is always at offset 1 */
	/* we use idxdb->str_mapped[0] to flag if the key is "in use" */
	*keyoffp = 1;
	idxdb->str_mapped[0] = 0;
	return RPMRC_OK;
    }
    keyl++;	/* include trailing 0 */
    while (idxdb->str_mappedlen - idxdb->keyend < keyl) {
	if (addkeypage(idxdb))
	    return RPMRC_FAIL;
    }
    memcpy(idxdb->str_mapped + idxdb->keyend, key, keyl);
    *keyoffp = idxdb->keyend;
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
	ent = idxdb->slot_mapped + 8 * h;
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
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
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
    char *tmpname = 0;
    unsigned int i, nslots, maxkeysize, slotsize, newlen;
    unsigned int keyend, keyoff, xmask;
    unsigned char *done;
    unsigned char *ent;

    nidxdb = &nidxdb_s;
    memset(nidxdb, 0, sizeof(*nidxdb));
    if (!idxdb->xdb) {
	tmpname = malloc(strlen(idxdb->filename) + 8);
	if (!tmpname)
	    return RPMRC_FAIL;
	sprintf(tmpname, "%s-XXXXXX", idxdb->filename);
	nidxdb->fd = mkstemp(tmpname);
	if (nidxdb->fd == -1)
	    return RPMRC_FAIL;
    }

    /* don't trust usedslots and dummyslots */
    nslots = 0;
    for (i = 0, ent = idxdb->slot_mapped; i < idxdb->nslots; i++, ent += 8) {
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
    nidxdb->slotoffset = nidxdb->pagesize;
    slotsize = (nslots * 12 + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    maxkeysize = (idxdb->keyend + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    if (maxkeysize < nidxdb->pagesize)
	maxkeysize = nidxdb->pagesize;
    for (xmask = 0x00010000; xmask < maxkeysize + 2 * nidxdb->pagesize; xmask <<= 1)
      ;
    xmask = ~(xmask - 1);
    nidxdb->xmask = xmask;

    newlen = nidxdb->pagesize + slotsize + maxkeysize;
    nidxdb->keyoffset = nidxdb->slotoffset + slotsize;
    keyend = 1 + 1;

    if (idxdb->xdb) {
	nidxdb->xdb = idxdb->xdb;
	nidxdb->xdbtag = idxdb->xdbtag;
	if (rpmxdbFindBlob(nidxdb->xdb, &nidxdb->xdbid_headslot, idxdb->xdbtag, 0 + 2, 1)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid_headslot, 0)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid_headslot, nidxdb->pagesize + slotsize)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbFindBlob(nidxdb->xdb, &nidxdb->xdbid_str, idxdb->xdbtag, 1 + 2, 1)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid_str, 0)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid_str, maxkeysize)) {
	    return RPMRC_FAIL;
	}
	if (rpmidxMap(nidxdb)) {
	    return RPMRC_FAIL;
	}
    } else {
	if (createempty(nidxdb, 0, newlen)) {
	    close(nidxdb->fd);
	    unlink(tmpname);
	    free(tmpname);
	    return RPMRC_FAIL;
	}
	nidxdb->head_mapped = mmap(0, newlen, PROT_READ | PROT_WRITE, MAP_SHARED, nidxdb->fd, 0);
	if (nidxdb->head_mapped == MAP_FAILED) {
	    close(nidxdb->fd);
	    unlink(tmpname);
	    free(tmpname);
	    return RPMRC_FAIL;
	}
	nidxdb->head_mappedlen = nidxdb->pagesize;
	nidxdb->slot_mapped = nidxdb->head_mapped + nidxdb->head_mappedlen;
	nidxdb->slot_mappedlen = slotsize;
	nidxdb->str_mapped = nidxdb->slot_mapped + nidxdb->slot_mappedlen;
	nidxdb->str_mappedlen = maxkeysize;
    }

    nidxdb->str_mapped[0] = 255;	/* empty string not yet in use */
    done = calloc(idxdb->nslots / 8 + 1, 1);
    if (!done) {
	rpmidxUnmap(nidxdb);
	close(nidxdb->fd);
	unlink(tmpname);
	free(tmpname);
	return RPMRC_FAIL;
    }
    for (i = 0, ent = idxdb->slot_mapped; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = le2ha(ent);
	char *key;
        int keyl;

	if (x == 0 || x == -1)
	    continue;
	if (done[i >> 3] & (1 << (i & 7))) {
	    continue;	/* we already did that one */
	}
	x &= ~idxdb->xmask;
	key = (char *)(idxdb->str_mapped + x);
	keyl = strlen(key);
	if (!keyl) {
	    /* special case empty string, see addnewkey() */
	    keyoff = 1;
	    nidxdb->str_mapped[0] = 0;
	} else {
	    keyoff = keyend;
	    memcpy(nidxdb->str_mapped + keyend, key, keyl + 1);
	    keyend += keyl + 1;
	}
	updatekey(key, keyl, idxdb, x, nidxdb, keyoff, done);
    }
    free(done);
    nidxdb->keyend = keyend;
    rpmidxWriteHeader(nidxdb);
    rpmidxUnmap(nidxdb);
    keyend = (keyend + 2 * nidxdb->pagesize) & ~(nidxdb->pagesize - 1);
    if (nidxdb->keyoffset + keyend < newlen) {
	if (nidxdb->xdb) {
	    rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid_str, keyend);
	} else {
	    ftruncate(nidxdb->fd, nidxdb->keyoffset + keyend);
	}
    }
    rpmidxUnmap(idxdb);
    if (idxdb->xdb) {
	if (rpmxdbRenameBlob(nidxdb->xdb, nidxdb->xdbid_headslot, idxdb->xdbtag, 0))
	    return RPMRC_FAIL;
	idxdb->xdbid_headslot = nidxdb->xdbid_headslot;
	if (rpmxdbRenameBlob(nidxdb->xdb, nidxdb->xdbid_str, idxdb->xdbtag, 1))
	    return RPMRC_FAIL;
	idxdb->xdbid_str = nidxdb->xdbid_str;
    } else {
	if (rename(tmpname, idxdb->filename)) {
	    close(nidxdb->fd);
	    unlink(tmpname);
	    free(tmpname);
	    return RPMRC_FAIL;
	}
	free(tmpname);
	idxdb->fd = nidxdb->fd;
    }
    if (rpmidxReadHeader(idxdb))
	return RPMRC_FAIL;
    return RPMRC_OK;
}

/* check if we need to rebuild the index */
static int rpmidxCheck(rpmidxdb idxdb)
{
    if (idxdb->usedslots * 2 > idxdb->nslots ||
	(idxdb->keyexcess > 4096 && idxdb->keyexcess * 4 > idxdb->keyend) ||
	idxdb->keyend >= ~idxdb->xmask) {
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
    if (rpmidxCheck(idxdb))
	return RPMRC_FAIL;
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->slot_mapped + 8 * h;
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
	ent = idxdb->slot_mapped + 8 * h;
    }
    if (freeh == -1) {
	idxdb->usedslots++;
	updateUsedslots(idxdb);
    } else {
	ent = idxdb->slot_mapped + 8 * freeh;
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
    if (rpmidxCheck(idxdb))
	return RPMRC_FAIL;
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
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
	    idxdb->str_mapped[0] = 255;
	} else {
	    /* zero out unused key so that rpmidxList no longer returns it */
	    memset(idxdb->str_mapped + keyoff, 0, keyl);
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
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
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
    if (!idxdb->str_mapped[0]) {
	/* empty string in use */
	keylist[0] = strdup("");
	if (!keylist[0]) {
	    free(keylist);
	    return RPMRC_FAIL;
	}
	nkeylist++;
    }
    for (koff = 2; koff < idxdb->keyend; koff++) {
	char *key = (char *)idxdb->str_mapped + koff;
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
    if (idxdb->xdb) {
	unsigned int headslotid, strid;
	if (rpmxdbFindBlob(idxdb->xdb, &headslotid, idxdb->xdbtag, 0, 0)) {
	    return RPMRC_FAIL;
	}
	if (rpmxdbFindBlob(idxdb->xdb, &strid, idxdb->xdbtag, 1, 0)) {
	    return RPMRC_FAIL;
	}
	if (headslotid && strid) {
	    idxdb->xdbid_headslot = headslotid;
	    idxdb->xdbid_str = strid;
	    return RPMRC_OK;	/* somebody else was faster */
	}
    } else {
	struct stat stb; 
	if (fstat(idxdb->fd, &stb)) {
	    return RPMRC_FAIL;
	}    
	if (stb.st_size) {
	    return RPMRC_OK;	/* somebody else was faster */
	}
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
    if (!idxdb)
        return RPMRC_FAIL;
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
	free(idxdb->filename);
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
	    free(idxdb->filename);
            free(idxdb);
            return RPMRC_FAIL;
        }
    }
    *idxdbp = idxdb;
    return RPMRC_OK;
}

int rpmidxOpenXdb(rpmidxdb *idxdbp, rpmpkgdb pkgdb, rpmxdb xdb, unsigned int xdbtag)
{
    rpmidxdb idxdb;
    unsigned int headslotid, strid;
    *idxdbp = 0;
    
    if (rpmpkgLock(pkgdb, 0))
	return RPMRC_FAIL;
    if (rpmxdbFindBlob(xdb, &headslotid, xdbtag, 0, 0)) {
        rpmpkgUnlock(pkgdb, 0);
	return RPMRC_FAIL;
    }
    if (rpmxdbFindBlob(xdb, &strid, xdbtag, 1, 0)) {
        rpmpkgUnlock(pkgdb, 0);
	return RPMRC_FAIL;
    }
    idxdb = calloc(1, sizeof(*idxdb));
    if (!idxdb) {
        rpmpkgUnlock(pkgdb, 0);
        return RPMRC_FAIL;
    }
    idxdb->fd = -1;
    idxdb->xdb = xdb;
    idxdb->xdbtag = xdbtag;
    idxdb->xdbid_headslot = headslotid;
    idxdb->xdbid_str = strid;
    idxdb->pkgdb = pkgdb;
    idxdb->pagesize = sysconf(_SC_PAGE_SIZE);
    if (!headslotid || !strid) {
	if (rpmidxInit(idxdb)) {
            free(idxdb);
	    rpmpkgUnlock(pkgdb, 0);
            return RPMRC_FAIL;
	}
    }
    *idxdbp = idxdb;
    rpmpkgUnlock(pkgdb, 0);
    return RPMRC_OK;
}

void rpmidxClose(rpmidxdb idxdb)
{
    rpmidxUnmap(idxdb);
    if (idxdb->fd >= 0) {
        close(idxdb->fd);
        idxdb->fd = -1; 
    }   
    if (idxdb->filename)
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
    if (idxdb->xdb) {
	printf("Xdb tag: %d, ids: %d %d\n", idxdb->xdbtag, idxdb->xdbid_headslot, idxdb->xdbid_str);
    } else {
	printf("Filename: %s\n", idxdb->filename);
    }
    printf("Generation: %u\n", idxdb->generation);
    printf("Slots: %u\n", idxdb->nslots);
    printf("Used slots: %u\n", idxdb->usedslots);
    printf("Dummy slots: %u\n", idxdb->dummyslots);
    printf("Key data size: %u\n", idxdb->keyend);
    printf("Key excess: %u\n", idxdb->keyexcess);
    printf("XMask : 0x%08x\n", idxdb->xmask);
    rpmpkgUnlock(idxdb->pkgdb, 0);
    return RPMRC_OK;
}
