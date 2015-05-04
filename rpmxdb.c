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

#include "rpmxdb.h"

#define RPMRC_OK 0
#define RPMRC_NOTFOUND 1
#define RPMRC_FAIL 2

typedef struct rpmxdb_s {
    rpmpkgdb pkgdb;             /* master database */
    char *filename;
    int fd;
    int flags;
    int mode;
    int rdonly;
    unsigned int pagesize;
    unsigned int generation;
    unsigned int slotnpages;

    unsigned char *mapped;
    unsigned int mappedlen;

    struct xdb_slot {
	unsigned int slotno;
	unsigned int blobtag;
	unsigned int subtag;
	void *mapped;
	unsigned int startpage;
	unsigned int pagecnt;
	void (*remapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize);
	void *remapcallbackdata;
	unsigned int next;
	unsigned int prev;
    } *slots;
    unsigned int nslots;
    unsigned int firstfree;
    unsigned int usedblobpages;
    unsigned int systempagesize;
    int dofsync;
} *rpmxdb;


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


#define XDB_MAGIC     ('R' | 'p' << 8 | 'm' << 16 | 'X' << 24)
#define XDB_VERSION	0

#define XDB_OFFSET_MAGIC	0
#define XDB_OFFSET_VERSION	4
#define XDB_OFFSET_GENERATION	8
#define XDB_OFFSET_SLOTNPAGES	12
#define XDB_OFFSET_PAGESIZE	16

/* must be multiple of SLOT_SIZE */
#define XDB_HEADER_SIZE		32

#define SLOT_MAGIC     ('S' | 'l' << 8 | 'o' << 16)

#define SLOT_SIZE 16
#define SLOT_START (XDB_HEADER_SIZE / SLOT_SIZE)

static void rpmxdbUnmap(rpmxdb xdb)
{
    munmap(xdb->mapped, xdb->mappedlen);
    xdb->mapped = 0;
    xdb->mappedlen = 0;
}

static int usedslots_cmp(const void *a, const void *b)
{
    struct xdb_slot *sa = *(struct xdb_slot **)a;
    struct xdb_slot *sb = *(struct xdb_slot **)b;
    if (sa->startpage == sb->startpage) {
      return sa->pagecnt > sb->pagecnt ? 1 : sa->pagecnt < sb->pagecnt ? -1 : 0;
    }
    return sa->startpage > sb->startpage ? 1 : -1;
}

static int rpmxdbReadHeader(rpmxdb xdb)
{
    struct xdb_slot *slot;
    unsigned int header[XDB_HEADER_SIZE / sizeof(unsigned int)];
    unsigned int slotnpages, pagesize, generation;
    unsigned int page, *lastfreep;
    unsigned char *pageptr;
    struct xdb_slot **usedslots, *lastslot;
    int i, nused, slotno;
    struct stat stb;
    size_t mapsize;

    if (xdb->mapped) {
	if (le2ha(xdb->mapped + XDB_OFFSET_GENERATION) == xdb->generation) {
	    return RPMRC_OK;
	}
	rpmxdbUnmap(xdb);
    }
    if (fstat(xdb->fd, &stb)) {
        return RPMRC_FAIL;
    }
    if (pread(xdb->fd, header, sizeof(header), 0) != sizeof(header)) {
	return RPMRC_FAIL;
    }
    if (le2ha((unsigned char *)header + XDB_OFFSET_MAGIC) != XDB_MAGIC)
	return RPMRC_FAIL;
    generation = le2ha((unsigned char *)header + XDB_OFFSET_GENERATION);
    slotnpages = le2ha((unsigned char *)header + XDB_OFFSET_SLOTNPAGES);
    pagesize = le2ha((unsigned char *)header + XDB_OFFSET_PAGESIZE);
    if (!slotnpages || !pagesize || stb.st_size % pagesize != 0)
	return RPMRC_FAIL;
    xdb->pagesize = pagesize;

    /* round up */
    mapsize = slotnpages * pagesize;
    mapsize = (mapsize + xdb->systempagesize - 1) & ~(xdb->systempagesize - 1);
    xdb->mapped = mmap(0, mapsize, xdb->rdonly ? PROT_READ : PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, 0);
    if (xdb->mapped == MAP_FAILED) {
	xdb->mapped = 0;
	return RPMRC_FAIL;
    }
    xdb->mappedlen = mapsize;

    /* read in all slots */
    xdb->firstfree = 0;
    xdb->nslots = slotnpages * (pagesize / SLOT_SIZE) - SLOT_START + 1;
    xdb->slots = calloc(xdb->nslots + 1, sizeof(struct xdb_slot));
    usedslots = calloc(xdb->nslots + 1, sizeof(int));
    nused = 0;
    slotno = 1;
    slot = xdb->slots + 1;
    xdb->usedblobpages = 0;
    lastfreep = &xdb->firstfree;
    for (page = 0, pageptr = xdb->mapped; page < slotnpages; page++, pageptr += pagesize) {
	unsigned int o;
	for (o = page ? 0 : SLOT_START * SLOT_SIZE; o < pagesize; o += SLOT_SIZE, slotno++, slot++) {
	    unsigned char *pp = pageptr + o;
	    slot->slotno = slotno;
	    slot->subtag = le2ha(pp);
	    if ((slot->subtag & 0x00ffffff) != SLOT_MAGIC) {
		free(xdb->slots);
		rpmxdbUnmap(xdb);
		return RPMRC_FAIL;
	    }
	    slot->subtag = (slot->subtag >> 24) & 255;
	    slot->blobtag = le2ha(pp + 4);
	    slot->startpage = le2ha(pp + 8);
	    slot->pagecnt = le2ha(pp + 12);
	    if (slot->pagecnt == 0 && slot->startpage)
		slot->startpage = slotnpages;
	    if (!slot->startpage) {
		*lastfreep = slotno;
		lastfreep = &slot->next;
	    } else {
		usedslots[nused++] = slot;
		xdb->usedblobpages += slot->pagecnt;
	    }
	}
    }
    if (nused > 1) {
	qsort(usedslots, nused, sizeof(*usedslots), usedslots_cmp);
    }
    /* now chain em */
    xdb->slots[0].pagecnt = slotnpages;
    lastslot = xdb->slots;
    for (i = 0; i < nused; i++, lastslot = slot) {
	slot = usedslots[i];
	if (lastslot->startpage + lastslot->pagecnt > slot->startpage) {
	    free(xdb->slots);
	    free(usedslots);
	    xdb->slots = 0;
	    rpmxdbUnmap(xdb);
	    return RPMRC_FAIL;
	}
	lastslot->next = slot->slotno;
	slot->prev = lastslot->slotno;
    }
    lastslot->next = xdb->nslots;
    xdb->slots[xdb->nslots].slotno = xdb->nslots;
    xdb->slots[xdb->nslots].prev = lastslot->slotno;
    xdb->slots[xdb->nslots].startpage = stb.st_size / pagesize;
    free(usedslots);
    xdb->generation = generation;
    xdb->slotnpages = slotnpages;
    return RPMRC_OK;
}

static int rpmxdbWriteHeader(rpmxdb xdb)
{
    if (!xdb->mapped)
	return RPMRC_FAIL;
    h2lea(XDB_MAGIC, xdb->mapped + XDB_OFFSET_MAGIC);
    h2lea(XDB_VERSION, xdb->mapped + XDB_OFFSET_VERSION);
    h2lea(xdb->generation, xdb->mapped + XDB_OFFSET_GENERATION);
    h2lea(xdb->slotnpages, xdb->mapped + XDB_OFFSET_SLOTNPAGES);
    h2lea(xdb->pagesize, xdb->mapped + XDB_OFFSET_PAGESIZE);
    return RPMRC_OK;
}

static void rpmxdbUpdateSlot(rpmxdb xdb, struct xdb_slot *slot)
{
    unsigned char *pp = xdb->mapped + (SLOT_START - 1 + slot->slotno) * SLOT_SIZE;
    h2lea(SLOT_MAGIC | (slot->subtag << 24), pp);
    h2lea(slot->blobtag, pp + 4);
    if (slot->pagecnt || !slot->startpage)
	h2lea(slot->startpage, pp + 8);
    else
	h2lea(1, pp + 8);	/* "empty but used" blobs always start at 1 */
    h2lea(slot->pagecnt, pp + 12);
    xdb->generation++;
    h2lea(xdb->generation, xdb->mapped + XDB_OFFSET_GENERATION);
}

static int rpmxdbWriteEmptyPages(rpmxdb xdb, unsigned int pageno, unsigned int count)
{
    unsigned char *page;
    if (!count)
	return RPMRC_OK;
    page = malloc(xdb->pagesize);
    if (!page)
	return RPMRC_FAIL;
    memset(page, 0, xdb->pagesize);
    for (; count; count--, pageno++) {
	if (pwrite(xdb->fd, page, xdb->pagesize, pageno * xdb->pagesize) != xdb->pagesize) {
	    free(page);
	    return RPMRC_FAIL;
	}
    }
    free(page);
    return RPMRC_OK;
}

static int rpmxdbWriteEmptySlotpage(rpmxdb xdb, int pageno)
{
    unsigned char *page;
    int i, spp;
    page = malloc(xdb->pagesize);
    if (!page)
	return RPMRC_FAIL;
    memset(page, 0, xdb->pagesize);
    spp = xdb->pagesize / SLOT_SIZE;	/* slots per page */
    for (i = pageno ? 0 : SLOT_START; i < spp; i++)
        h2le(SLOT_MAGIC, page + i * SLOT_SIZE);
    if (!pageno) {
	/* only used when called from InitInternal */
	if (xdb->mapped) {
	    free(page);
	    return RPMRC_FAIL;
	}
	xdb->mapped = page;
	rpmxdbWriteHeader(xdb);
	xdb->mapped = 0;
    }
    if (pwrite(xdb->fd, page, xdb->pagesize, pageno * xdb->pagesize) != xdb->pagesize) {
	free(page);
	return RPMRC_FAIL;
    }
    free(page);
    return RPMRC_OK;
}

static int rpmxdbInitInternal(rpmxdb xdb)
{
    struct stat stb;
    if (fstat(xdb->fd, &stb)) {
        return RPMRC_FAIL;
    }
    if (stb.st_size == 0) {
        xdb->slotnpages = 1;
        xdb->generation++;
	xdb->pagesize = sysconf(_SC_PAGE_SIZE);
        if (rpmxdbWriteEmptySlotpage(xdb, 0)) {
            return RPMRC_FAIL;
        }
    }
    return RPMRC_OK;
}

/* we use the master pdb for locking */
int rpmxdbLock(rpmxdb xdb, int excl)
{
    if (excl && xdb->rdonly)
        return RPMRC_FAIL;
    return rpmpkgLock(xdb->pkgdb, excl);
}

int rpmxdbUnlock(rpmxdb xdb, int excl)
{
    return rpmpkgUnlock(xdb->pkgdb, excl);
}

static int rpmxdbInit(rpmxdb xdb)
{
    int rc;

    if (rpmxdbLock(xdb, 1))
        return RPMRC_FAIL;
    rc = rpmxdbInitInternal(xdb);
    rpmxdbUnlock(xdb, 1);
    return rc;
}

int rpmxdbOpen(rpmxdb *xdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode)
{
    struct stat stb;
    rpmxdb xdb;

    *xdbp = 0;
    xdb = calloc(1, sizeof(*xdb));
    xdb->pkgdb = pkgdb;
    xdb->filename = strdup(filename);
    xdb->systempagesize = sysconf(_SC_PAGE_SIZE);
    if (!xdb->filename) {
	free(xdb);
	return RPMRC_FAIL;
    }
    if ((flags & (O_RDONLY|O_RDWR)) == O_RDONLY)
	xdb->rdonly = 1;
    if ((xdb->fd = open(filename, flags, mode)) == -1) {
	free(xdb->filename);
	free(xdb);
	return RPMRC_FAIL;
    }
    if (fstat(xdb->fd, &stb)) {
	close(xdb->fd);
	free(xdb->filename);
	free(xdb);
	return RPMRC_FAIL;
    }
    if (stb.st_size == 0) {
	if (rpmxdbInit(xdb)) {
	    close(xdb->fd);
	    free(xdb->filename);
	    free(xdb);
	    return RPMRC_FAIL;
	}
    }
    xdb->flags = flags;
    xdb->mode = mode;
    xdb->dofsync = 1;
    *xdbp = xdb;
    return RPMRC_OK;
}

static int mapslot(rpmxdb xdb, struct xdb_slot *slot)
{
    void *mapped;
    size_t off, size, shift;

    size = slot->pagecnt * xdb->pagesize;
    off = slot->startpage * xdb->pagesize;
    shift = 0;
    if (xdb->pagesize != xdb->systempagesize) {
	shift = off & (xdb->systempagesize - 1);
	off -= shift;
	size += shift;
	size = (size + xdb->systempagesize - 1) & (xdb->systempagesize - 1);
    }
    mapped = mmap(0, size, xdb->rdonly ? PROT_READ : PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, off);
    if (mapped == MAP_FAILED)
	return RPMRC_FAIL;
    slot->mapped = mapped + shift;
    return RPMRC_OK;
}

static void unmapslot(rpmxdb xdb, struct xdb_slot *slot)
{
    size_t size;
    void *mapped = slot->mapped;
    size = slot->pagecnt * xdb->pagesize;
    if (xdb->pagesize != xdb->systempagesize) {
	size_t off = slot->startpage * xdb->pagesize;
	size_t shift = off & (xdb->systempagesize - 1);
	mapped -= shift;
	size += shift;
	size = (size + xdb->systempagesize - 1) & (xdb->systempagesize - 1);
    }
    munmap(mapped, size);
    slot->mapped = 0;
}

static int remapslot(rpmxdb xdb, struct xdb_slot *slot, unsigned int newpagecnt)
{
    void *mapped;
    size_t off, oldsize, newsize, shift;
    oldsize = slot->pagecnt * xdb->pagesize;
    newsize = newpagecnt * xdb->pagesize;
    off = slot->startpage * xdb->pagesize;
    shift = 0;
    if (xdb->pagesize != xdb->systempagesize) {
	off = slot->startpage * xdb->pagesize;
	shift = off & (xdb->systempagesize - 1);
	off -= shift;
	oldsize += shift;
	oldsize = (oldsize + xdb->systempagesize - 1) & (xdb->systempagesize - 1);
	newsize += shift;
	newsize = (newsize + xdb->systempagesize - 1) & (xdb->systempagesize - 1);
    }
    if (slot->mapped)
	mapped = mremap(slot->mapped - shift, oldsize, newsize, MREMAP_MAYMOVE);
    else
	mapped = mmap(0, newsize, xdb->rdonly ? PROT_READ : PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, off);
    if (mapped == MAP_FAILED)
	return RPMRC_FAIL;
    slot->mapped = mapped + shift;
    slot->pagecnt = newpagecnt;
    return RPMRC_OK;
}

void rpmxdbClose(rpmxdb xdb)
{
    struct xdb_slot *slot;
    int i;

    for (i = 1, slot = xdb->slots + 1; i < xdb->nslots; i++, slot++) {
	if (slot->mapped) {
	    unmapslot(xdb, slot);
	    slot->remapcallback(xdb, slot->remapcallbackdata, 0, 0);
	}
    }
    if (xdb->fd)
	close(xdb->fd);
    free(xdb->filename);
    free(xdb);
}

/* moves the blob to a given new location (possibly resizeing) */
static int moveblobto(rpmxdb xdb, struct xdb_slot *oldslot, struct xdb_slot *afterslot, unsigned int newpagecnt)
{
    struct xdb_slot *nextslot;
    unsigned int newstartpage, oldpagecnt;
    unsigned int tocopy;
    int didmap;

    newstartpage = afterslot->startpage + afterslot->pagecnt;
    nextslot = xdb->slots + afterslot->next;

    /* make sure there's enough room */
    if (newpagecnt > nextslot->startpage - newstartpage)
	return RPMRC_FAIL;

#if 0
    printf("moveblobto %d %d %d %d, afterslot %d\n", oldslot->startpage, oldslot->pagecnt, newstartpage, newpagecnt, afterslot->slotno);
#endif
    /* map old content */
    didmap = 0;
    oldpagecnt = oldslot->pagecnt;
    if (!oldslot->mapped && oldpagecnt) {
	if (mapslot(xdb, oldslot))
	    return RPMRC_FAIL;
        didmap = 1;
    }

    /* copy content */
    tocopy = newpagecnt > oldpagecnt ? oldpagecnt : newpagecnt;
    if (tocopy && pwrite(xdb->fd, oldslot->mapped, tocopy * xdb->pagesize, newstartpage * xdb->pagesize) != tocopy * xdb->pagesize) {
	if (didmap)
	    unmapslot(xdb, oldslot);
	return RPMRC_FAIL;
    }
    /* zero out new pages */
    if (newpagecnt > oldpagecnt) {
	if (rpmxdbWriteEmptyPages(xdb, newstartpage + oldpagecnt, newpagecnt - oldpagecnt)) {
	    if (didmap)
		unmapslot(xdb, oldslot);
	    return RPMRC_FAIL;
	}
    }

    if (oldslot->mapped)
	unmapslot(xdb, oldslot);

    /* set new offset and position */
    oldslot->startpage = newstartpage;
    oldslot->pagecnt = newpagecnt;
    rpmxdbUpdateSlot(xdb, oldslot);
    xdb->usedblobpages -= oldpagecnt;
    xdb->usedblobpages += newpagecnt;

    if (afterslot != oldslot && nextslot != oldslot) {
	/* remove from old chain */
	xdb->slots[oldslot->prev].next = oldslot->next;
	xdb->slots[oldslot->next].prev = oldslot->prev;

	/* chain into new position, between lastslot and nextslot */
	oldslot->prev = afterslot->slotno;
	afterslot->next = oldslot->slotno;

	oldslot->next = nextslot->slotno;
	nextslot->prev = oldslot->slotno;
    }

    /* map again (if needed) */
    if (oldslot->remapcallback) {
	if (newpagecnt) {
	    if (mapslot(xdb, oldslot))
		oldslot->mapped = 0;	/* XXX: HELP, what can we do here? */
	}
	oldslot->remapcallback(xdb, oldslot->remapcallbackdata, oldslot->mapped, oldslot->mapped ? oldslot->pagecnt * xdb->pagesize : 0);
    }
    return RPMRC_OK;
}

/* moves the blob to a new location (possibly resizeing) */
static int moveblob(rpmxdb xdb, struct xdb_slot *oldslot, unsigned int newpagecnt)
{
    struct xdb_slot *slot, *lastslot;
    unsigned int nslots;
    unsigned int freecnt;
    int i;

    nslots = xdb->nslots;
    freecnt = 0;
    lastslot = xdb->slots;
    for (i = xdb->slots[0].next; ; lastslot = slot, i = slot->next) {
	slot = xdb->slots + i;
	freecnt = slot->startpage - (lastslot->startpage + lastslot->pagecnt);
	if (freecnt >= newpagecnt)
	    break;
	if (i == nslots)
	    break;
    }
    if (i == nslots && newpagecnt > freecnt) {
	/* need to grow the file */
	if (rpmxdbWriteEmptyPages(xdb, slot->startpage, newpagecnt - freecnt)) {
	    return RPMRC_FAIL;
	}
	slot->startpage += newpagecnt - freecnt;
    }
    return moveblobto(xdb, oldslot, lastslot, newpagecnt);
}

/* move the two blobs at the end of our file to the free area after the provided slot */
static int moveblobstofront(rpmxdb xdb, struct xdb_slot *afterslot)
{
    struct xdb_slot *slot1, *slot2;
    unsigned int freestart = afterslot->startpage + afterslot->pagecnt;
    unsigned int freecount = xdb->slots[afterslot->next].startpage - freestart;

    slot1 = xdb->slots + xdb->slots[xdb->nslots].prev;
    if (slot1 == xdb->slots)
	slot1 = slot2 = 0;
    else {
	slot2 = xdb->slots + slot1->prev;
	if (slot2 == xdb->slots)
	    slot2 = 0;
    }
    if (slot1->pagecnt < slot2->pagecnt) {
	struct xdb_slot *tmp = slot1;
	slot1 = slot2;
	slot2 = tmp;
    }
    if (slot1 && slot1->pagecnt && slot1->pagecnt <= freecount && slot1->startpage > freestart) {
	if (moveblobto(xdb, slot1, afterslot, slot1->pagecnt))
	    return RPMRC_FAIL;
	freestart += slot1->pagecnt;
	freecount -= slot1->pagecnt;
	afterslot = slot1;
    }
    if (slot2 && slot2->pagecnt && slot2->pagecnt <= freecount && slot2->startpage > freestart) {
	if (moveblobto(xdb, slot2, afterslot, slot2->pagecnt))
	    return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

/* add a single page containing empty slots */
static int addslotpage(rpmxdb xdb)
{
    unsigned char *newaddr;
    struct xdb_slot *slot;
    int i, spp, nslots;
    size_t newmappedlen;

    if (xdb->firstfree)
	return RPMRC_FAIL;
    /* move first blob if needed */
    nslots = xdb->nslots;
    for (i = xdb->slots[0].next; i != nslots; i = slot->next) {
	slot = xdb->slots + i;
	if (slot->pagecnt)
	    break;
    }
    if (i != nslots && slot->pagecnt && slot->startpage == xdb->slotnpages) {
	/* the blob at this slot is in the way. move it. */
	if (moveblob(xdb, slot, slot->pagecnt))
	    return RPMRC_FAIL;
    }

    spp = xdb->pagesize / SLOT_SIZE;	/* slots per page */
    slot = realloc(xdb->slots, (nslots + 1 + spp) * sizeof(*slot));
    if (!slot)
	return RPMRC_FAIL;
    xdb->slots = slot;

    if (rpmxdbWriteEmptySlotpage(xdb, xdb->slotnpages)) {
	return RPMRC_FAIL;
    }
    newmappedlen = xdb->slotnpages * xdb->pagesize + xdb->pagesize;
    newmappedlen = (newmappedlen + xdb->systempagesize - 1) & ~(xdb->systempagesize - 1);
    newaddr = mremap(xdb->mapped, xdb->mappedlen, newmappedlen, MREMAP_MAYMOVE);
    if (newaddr == MAP_FAILED)
	return RPMRC_FAIL;
    xdb->mapped = newaddr;
    xdb->mappedlen = newmappedlen;
    xdb->slotnpages++;
    xdb->generation++;
    rpmxdbWriteHeader(xdb);

    /* fixup empty but used slots */
    for (i = xdb->slots[0].next; i != nslots; i = slot->next) {
	slot = xdb->slots + i;
	if (slot->startpage >= xdb->slotnpages)
	    break;
	slot->startpage = xdb->slotnpages;
	if (slot->pagecnt)
	    abort();
    }

    /* move tail element to the new end */
    slot = xdb->slots + nslots + spp;
    *slot = xdb->slots[nslots];
    slot->slotno = nslots + spp;
    xdb->slots[slot->prev].next = slot->slotno;
    xdb->nslots += spp;

    /* add new free slots to the firstfree chain */
    memset(xdb->slots + nslots, 0, sizeof(*slot) * spp);
    for (i = 0; i < spp - 1; i++) {
	xdb->slots[nslots + i].slotno = nslots + i;
	xdb->slots[nslots + i].next = i + 1;
    }
    xdb->slots[nslots + i].slotno = nslots + i;
    xdb->firstfree = nslots;
    return RPMRC_OK;
}

static int createblob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag)
{
    struct xdb_slot *slot;
    unsigned int id;

    if (subtag > 255)
	return RPMRC_FAIL;
    if (!xdb->firstfree) {
	if (addslotpage(xdb))
	    return RPMRC_FAIL;
    }
    id = xdb->firstfree;
    slot = xdb->slots + xdb->firstfree;
    xdb->firstfree = slot->next;

    slot->mapped = 0;
    slot->blobtag = blobtag;
    slot->subtag = subtag;
    slot->startpage = xdb->slotnpages;
    slot->pagecnt = 0;
    rpmxdbUpdateSlot(xdb, slot);
    /* enqueue */
    slot->prev = 0;
    slot->next = xdb->slots[0].next;
    xdb->slots[slot->next].prev = id;
    xdb->slots[0].next = id;
#if 0
    printf("createblob #%d %d/%d\n", id, blobtag, subtag);
#endif
    if (slot->slotno != id)
	abort();
    if (slot->mapped)
	abort();
    *idp = id;
    return RPMRC_OK;
}

int rpmxdbFindBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag, int flags)
{
    struct xdb_slot *slot;
    unsigned int i, nslots;
    if (rpmxdbLock(xdb, flags ? 1 : 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, flags ? 1 : 0);
        return RPMRC_FAIL;
    }
    nslots = xdb->nslots;
    slot = 0;
    for (i = xdb->slots[0].next; i != nslots; i = slot->next) {
	slot = xdb->slots + i;
	if (slot->blobtag == blobtag && slot->subtag == subtag)
	    break;
    }
    if (i == nslots)
	i = 0;
    if (i && (flags & RPMXDB_TRUNC) != 0) {
	if (rpmxdbResizeBlob(xdb, i, 0)) {
	    rpmxdbUnlock(xdb, flags ? 1 : 0);
	    return RPMRC_FAIL;
	}
    }
    if (!i && (flags & RPMXDB_CREAT) != 0) {
	if (createblob(xdb, &i, blobtag, subtag)) {
	    rpmxdbUnlock(xdb, flags ? 1 : 0);
	    return RPMRC_FAIL;
	}
    }
    *idp = i;
    rpmxdbUnlock(xdb, flags ? 1 : 0);
    return RPMRC_OK;
}

int rpmxdbDelBlob(rpmxdb xdb, unsigned int id)
{
    struct xdb_slot *slot;
    if (!id)
	return RPMRC_FAIL;
    if (rpmxdbLock(xdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_OK;
    }
    if (slot->mapped) {
	unmapslot(xdb, slot);
	slot->remapcallback(xdb, slot->remapcallbackdata, 0, 0);
    }
    /* remove from old chain */
    xdb->slots[slot->prev].next = slot->next;
    xdb->slots[slot->next].prev = slot->prev;
    xdb->usedblobpages -= slot->pagecnt;

    if (xdb->usedblobpages * 2 < xdb->slots[xdb->nslots].startpage && (slot->startpage + slot->pagecnt) * 2 < xdb->slots[xdb->nslots].startpage) {
	/* freed in first half of pages, move last two blobs if we can */
	moveblobstofront(xdb, xdb->slots + slot->prev);
    }

    /* zero slot */
    memset(slot, 0, sizeof(*slot));
    slot->slotno = id;
    rpmxdbUpdateSlot(xdb, slot);

    /* enqueue into free chain */
    slot->next = xdb->firstfree;
    xdb->firstfree = slot->slotno;

    /* check if we should truncate the file */
    slot = xdb->slots + xdb->slots[xdb->nslots].prev;
    if (slot->startpage + slot->pagecnt < xdb->slots[xdb->nslots].startpage / 4 * 3) {
	unsigned int newend = slot->startpage + slot->pagecnt;
	if (!ftruncate(xdb->fd, newend * xdb->pagesize))
	    xdb->slots[xdb->nslots].startpage = newend;
    }

    rpmxdbUnlock(xdb, 1);
    return RPMRC_OK;
}

int rpmxdbResizeBlob(rpmxdb xdb, unsigned int id, size_t newsize)
{
    struct xdb_slot *slot;
    unsigned int oldpagecnt, newpagecnt;
    if (!id)
	return RPMRC_FAIL;
    if (rpmxdbLock(xdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    oldpagecnt = slot->pagecnt;
    newpagecnt = (newsize + xdb->pagesize - 1) / xdb->pagesize;
    if (newpagecnt == oldpagecnt) {
	/* no size change */
	rpmxdbUnlock(xdb, 1);
        return RPMRC_OK;
    }
    if (!newpagecnt) {
	/* special case: zero size blob, no longer mapped */
	if (slot->mapped)
	    unmapslot(xdb, slot);
	slot->pagecnt = 0;
	slot->startpage = xdb->slotnpages;
	/* remove from old chain */
	xdb->slots[slot->prev].next = slot->next;
	xdb->slots[slot->next].prev = slot->prev;
	/* enqueue into head */
	slot->prev = 0;
	slot->next = xdb->slots[0].next;
	xdb->slots[slot->next].prev = slot->slotno;
	xdb->slots[0].next = slot->slotno;
	rpmxdbUpdateSlot(xdb, slot);
	xdb->usedblobpages -= oldpagecnt;
	if (slot->remapcallback)
	    slot->remapcallback(xdb, slot->remapcallbackdata, 0, 0);
    } else if (newpagecnt <= xdb->slots[slot->next].startpage - slot->startpage) {
	/* can do it inplace */
	if (newpagecnt > oldpagecnt) {
	    /* zero new pages */
	    if (rpmxdbWriteEmptyPages(xdb, slot->startpage + oldpagecnt, newpagecnt - oldpagecnt)) {
		rpmxdbUnlock(xdb, 1);
		return RPMRC_FAIL;
	    }
	}
	if (slot->remapcallback) {
	    if (remapslot(xdb, slot, newpagecnt)) {
		rpmxdbUnlock(xdb, 1);
		return RPMRC_FAIL;
	    }
	} else {
	    if (slot->mapped)
		unmapslot(xdb, slot);
	    slot->pagecnt = newpagecnt;
	}
	rpmxdbUpdateSlot(xdb, slot);
	xdb->usedblobpages -= oldpagecnt;
	xdb->usedblobpages += newpagecnt;
	if (slot->remapcallback)
	    slot->remapcallback(xdb, slot->remapcallbackdata, slot->mapped, slot->pagecnt * xdb->pagesize);
    } else {
	if (moveblob(xdb, slot, newpagecnt)) {
	    rpmxdbUnlock(xdb, 1);
	    return RPMRC_OK;
	}
    }
    rpmxdbUnlock(xdb, 1);
    return RPMRC_OK;
}

int rpmxdbMapBlob(rpmxdb xdb, unsigned int id, void (*remapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize), void *remapcallbackdata)
{
    struct xdb_slot *slot;
    if (!id || !remapcallback)
	return RPMRC_FAIL;
    if (rpmxdbLock(xdb, 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, 0);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmxdbUnlock(xdb, 0);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage || slot->mapped) {
	rpmxdbUnlock(xdb, 0);
        return RPMRC_FAIL;
    }
    if (slot->pagecnt) {
	if (mapslot(xdb, slot)) {
	    rpmxdbUnlock(xdb, 0);
	    return RPMRC_FAIL;
	}
    }
    slot->remapcallback = remapcallback;
    slot->remapcallbackdata = remapcallbackdata;
    remapcallback(xdb, remapcallbackdata, slot->mapped, slot->mapped ? slot->pagecnt * xdb->pagesize : 0);
    rpmxdbUnlock(xdb, 0);
    return RPMRC_OK;
}

int rpmxdbUnmapBlob(rpmxdb xdb, unsigned int id)
{
    struct xdb_slot *slot;
    if (!id)
	return RPMRC_OK;
    if (id >= xdb->nslots)
	return RPMRC_FAIL;
    slot = xdb->slots + id;
    if (slot->mapped) {
	unmapslot(xdb, slot);
	slot->remapcallback(xdb, slot->remapcallbackdata, 0, 0);
    }
    slot->remapcallback = 0;
    slot->remapcallbackdata = 0;
    return RPMRC_OK;
}

int rpmxdbRenameBlob(rpmxdb xdb, unsigned int id, unsigned int blobtag, unsigned int subtag)
{
    struct xdb_slot *slot;
    unsigned int otherid;

    if (!id || subtag > 255)
	return RPMRC_FAIL;
    if (rpmxdbLock(xdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmxdbUnlock(xdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
#if 0
    printf("rpmxdbRenameBlob #%d %d/%d -> %d/%d\n", id, slot->blobtag, slot->subtag, blobtag, subtag);
#endif
    if (!slot->startpage) {
	rpmxdbUnlock(xdb, 1);
	return RPMRC_FAIL;
    }
    if (slot->blobtag == blobtag && slot->subtag == subtag) {
	rpmxdbUnlock(xdb, 1);
	return RPMRC_OK;
    }
    if (rpmxdbFindBlob(xdb, &otherid, blobtag, subtag, 0)) {
	rpmxdbUnlock(xdb, 1);
	return RPMRC_FAIL;
    }
    if (otherid) {
#if 0
	printf("(replacing #%d)\n", otherid);
#endif
	if (rpmxdbDelBlob(xdb, otherid)) {
	    rpmxdbUnlock(xdb, 1);
	    return RPMRC_FAIL;
	}
    }
    slot = xdb->slots + id;
    slot->blobtag = blobtag;
    slot->subtag = subtag;
    rpmxdbUpdateSlot(xdb, slot);
    rpmxdbUnlock(xdb, 1);
    return RPMRC_OK;
}

int rpmxdbFsyncBlob(rpmxdb xdb, unsigned int id)
{
    return RPMRC_OK;
}

void rpmxdbSetFsync(rpmxdb xdb, int dofsync)
{
    xdb->dofsync = dofsync;
}

int rpmxdbStats(rpmxdb xdb)
{
    struct xdb_slot *slot;
    unsigned int i, nslots;

    if (rpmxdbLock(xdb, 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmxdbUnlock(xdb, 0);
        return RPMRC_FAIL;
    }
    nslots = xdb->nslots;
    printf("--- XDB Stats\n");
    printf("Filename: %s\n", xdb->filename);
    printf("Generation: %d\n", xdb->generation);
    printf("Slot pages: %d\n", xdb->slotnpages);
    printf("Blob pages: %d\n", xdb->usedblobpages);
    printf("Free pages: %d\n", xdb->slots[nslots].startpage - xdb->usedblobpages - xdb->slotnpages);
    printf("Pagesize: %d\n", xdb->pagesize);
    for (i = 1, slot = xdb->slots + i; i < nslots; i++, slot++) {
	if (!slot->startpage)
	    continue;
	printf("%2d: tag %d/%d, startpage %d, pagecnt %d%s\n", i, slot->blobtag, slot->subtag, slot->startpage, slot->pagecnt, slot->remapcallbackdata ? ", mapped" : "");
    }
#if 0
    printf("Again in offset order:\n");
    for (i = xdb->slots[0].next; i != nslots; i = slot->next) {
	slot = xdb->slots + i;
	printf("%2d: tag %d/%d, startpage %d, pagecnt %d%s\n", i, slot->blobtag, slot->subtag, slot->startpage, slot->pagecnt, slot->remapcallbackdata ? ", mapped" : "");
    }
#endif
#if 0
    printf("Free chain:\n");
    for (i = xdb->firstfree; i; i = slot->next) {
	slot = xdb->slots + i;
	printf("%2d [%2d]: tag %d/%d, startpage %d, pagecnt %d%s\n", i, slot->slotno, slot->blobtag, slot->subtag, slot->startpage, slot->pagecnt, slot->remapcallbackdata ? ", mapped" : "");
    }
#endif
    rpmxdbUnlock(xdb, 0);
    return RPMRC_OK;
}

