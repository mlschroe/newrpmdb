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

#define RPMRC_FAIL 1
#define RPMRC_OK 0

typedef struct rpmxdb_s {
    rpmpkgdb pkgdb;             /* master database */
    char *filename;
    int fd;
    int flags;
    int mode;
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
#define SLOT_MAGIC     ('S' | 'l' << 8 | 'o' << 16)

#define SLOT_START 2
#define SLOT_SIZE 16

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
    unsigned int header[4];
    unsigned int slotnpages, pagesize, generation;
    unsigned int page, *lastfreep;
    unsigned char *pageptr;
    struct xdb_slot **usedslots, *lastslot;
    int i, nused, slotno;
    struct stat stb;

    if (xdb->mapped) {
	if (le2ha(xdb->mapped + 4) == xdb->generation) {
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
    if (le2ha((unsigned char *)header) != XDB_MAGIC)
	return RPMRC_FAIL;
    generation = le2ha((unsigned char *)header + 4);
    slotnpages = le2ha((unsigned char *)header + 8);
    pagesize = le2ha((unsigned char *)header + 12);
    if (!slotnpages || !pagesize || stb.st_size % pagesize != 0)
	return RPMRC_FAIL;
    xdb->pagesize = pagesize;
    xdb->mapped = mmap(0, slotnpages * pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, 0);
    if (xdb->mapped == MAP_FAILED) {
	xdb->mapped = 0;
	return RPMRC_FAIL;
    }
    /* read in all slots */
    xdb->firstfree = 0;
    xdb->nslots = slotnpages * (pagesize / SLOT_SIZE) - SLOT_START + 1;
    xdb->slots = calloc(xdb->nslots + 1, sizeof(struct xdb_slot));
    usedslots = calloc(slotnpages * (pagesize / SLOT_SIZE) - SLOT_START + 2, sizeof(int));
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
    h2lea(XDB_MAGIC, xdb->mapped);
    h2lea(xdb->generation, xdb->mapped + 4);
    h2lea(xdb->slotnpages, xdb->mapped + 8);
    h2lea(xdb->pagesize, xdb->mapped + 12);
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
	h2lea(1, pp + 8);	/* empty but used slots always start at 1 */
    h2lea(slot->pagecnt, pp + 12);
    xdb->generation++;
    h2lea(xdb->generation, xdb->mapped + 4);
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
	h2le(XDB_MAGIC, page);
	h2le(xdb->generation, page + 4);
	h2le(xdb->slotnpages, page + 8);
	h2le(xdb->pagesize, page + 12);
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

static int rpmxdbInit(rpmxdb xdb)
{
    int rc;

    if (rpmpkgLock(xdb->pkgdb, 1))
        return RPMRC_FAIL;
    rc = rpmxdbInitInternal(xdb);
    rpmpkgUnlock(xdb->pkgdb, 1);
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
    if (!xdb->filename) {
	free(xdb);
	return RPMRC_FAIL;
    }
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

void rpmxdbClose(rpmxdb xdb)
{
    struct xdb_slot *slot;
    int i;

    for (i = 1, slot = xdb->slots + 1; i < xdb->nslots; i++, slot++) {
	if (slot->mapped) {
	    munmap(slot->mapped, slot->pagecnt * xdb->pagesize);
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
	oldslot->mapped = mmap(0, oldpagecnt * xdb->pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, oldslot->startpage * xdb->pagesize);
	if (oldslot->mapped == MAP_FAILED) {
	    oldslot->mapped = 0;
	    return RPMRC_FAIL;
	}
        didmap = 1;
    }

    /* copy content */
    tocopy = newpagecnt > oldpagecnt ? oldpagecnt : newpagecnt;
    if (tocopy && pwrite(xdb->fd, oldslot->mapped, tocopy * xdb->pagesize, newstartpage * xdb->pagesize) != tocopy * xdb->pagesize) {
	if (didmap) {
	    munmap(oldslot->mapped, oldpagecnt * xdb->pagesize);
	    oldslot->mapped = 0;
	}
	return RPMRC_FAIL;
    }
    /* zero out new pages */
    if (newpagecnt > oldpagecnt) {
	if (rpmxdbWriteEmptyPages(xdb, newstartpage + oldpagecnt, newpagecnt - oldpagecnt)) {
	    if (didmap) {
		munmap(oldslot->mapped, oldpagecnt * xdb->pagesize);
		oldslot->mapped = 0;
	    }
	    return RPMRC_FAIL;
	}
    }

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
    if (oldslot->mapped)
	munmap(oldslot->mapped, oldpagecnt * xdb->pagesize);
    oldslot->mapped = 0;
    if (oldslot->remapcallback) {
	if (newpagecnt) {
	    oldslot->mapped = mmap(0, newpagecnt * xdb->pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, newstartpage * xdb->pagesize);
	    if (oldslot->mapped == MAP_FAILED)
		oldslot->mapped = 0;	/* XXX: HELP */
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

static int addslotpage(rpmxdb xdb)
{
    unsigned char *newaddr;
    struct xdb_slot *slot;
    int i, spp, nslots;

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
	if (moveblob(xdb, slot, slot->pagecnt))
	    return RPMRC_FAIL;
    }

    spp = xdb->pagesize / SLOT_SIZE;	/* slots per page */
    slot = realloc(xdb->slots, (nslots + 1 + spp) * sizeof(*slot));
    if (!slot) {
	return RPMRC_FAIL;
    }
    xdb->slots = slot;

    if (rpmxdbWriteEmptySlotpage(xdb, xdb->slotnpages)) {
	return RPMRC_FAIL;
    }
    newaddr = mremap(xdb->mapped, xdb->mappedlen, xdb->slotnpages * xdb->pagesize + xdb->pagesize, MREMAP_MAYMOVE);
    if (newaddr == MAP_FAILED)
	return RPMRC_FAIL;
    xdb->slotnpages++;
    xdb->generation++;
    rpmxdbWriteHeader(xdb);

    /* fixup empty but used slots */
    for (i = xdb->slots[0].next; i != nslots; i = slot->next) {
	slot = xdb->slots + i;
	if (slot->startpage < xdb->slotnpages) {
	    slot->startpage = xdb->slotnpages;
	    if (slot->pagecnt)
		abort();
	}
	else
	    break;
    }

    xdb->mapped = newaddr;
    xdb->mappedlen = xdb->slotnpages * xdb->pagesize;

    slot = xdb->slots + nslots + spp;
    *slot = xdb->slots[nslots];
    slot->slotno = nslots + spp;
    xdb->slots[slot->prev].next = slot->slotno;
    memset(xdb->slots + nslots, 0, sizeof(*slot) * spp);
    /* add new free slots */
    for (i = 0; i < spp - 1; i++) {
	xdb->slots[nslots + i].slotno = nslots + i;
	xdb->slots[nslots + i].next = i + 1;
    }
    xdb->firstfree = nslots;
    xdb->nslots += spp;
    return RPMRC_OK;
}

static int createblob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag)
{
    struct xdb_slot *slot;
    unsigned int id;

    if (subtag > 255)
	return RPMRC_FAIL;
    if (!xdb->firstfree) {
abort();
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

int rpmxdbFindBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag, int create)
{
    struct xdb_slot *slot;
    unsigned int i, nslots;
    if (rpmpkgLock(xdb->pkgdb, create ? 1 : 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, create ? 1 : 0);
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
    if (!i && create) {
	if (createblob(xdb, &i, blobtag, subtag)) {
	    rpmpkgUnlock(xdb->pkgdb, create ? 1 : 0);
	    return RPMRC_FAIL;
	}
    }
    *idp = i;
    rpmpkgUnlock(xdb->pkgdb, create ? 1 : 0);
    return RPMRC_OK;
}

int rpmxdbDeleteBlob(rpmxdb xdb, unsigned int id)
{
    struct xdb_slot *slot;
    if (!id)
	return RPMRC_FAIL;
    if (rpmpkgLock(xdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_OK;
    }
    if (slot->mapped) {
	munmap(slot->mapped, slot->pagecnt * xdb->pagesize);
	slot->mapped = 0;
	slot->remapcallback(xdb, slot->remapcallbackdata, 0, 0);
    }
    /* remove from old chain */
    xdb->slots[slot->prev].next = slot->next;
    xdb->slots[slot->next].prev = slot->prev;
    xdb->usedblobpages -= slot->pagecnt;

    if (xdb->usedblobpages * 2 < xdb->slots[xdb->nslots].startpage && (slot->startpage + slot->pagecnt) * 2 < xdb->slots[xdb->nslots].startpage) {
	/* freed in first half of pages, move last two blobs if we can */
	struct xdb_slot *slot1, *slot2, *afterslot;
	unsigned int freestart, freecount;
	afterslot = xdb->slots + slot->prev;
	freestart = afterslot->startpage + afterslot->pagecnt;
	freecount = xdb->slots[afterslot->next].startpage - freestart;

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
	if (slot1 && slot1->pagecnt < freecount) {
	    if (moveblobto(xdb, slot1, afterslot, slot1->pagecnt)) {
		/* hmm */
		slot2 = 0;
	    } else {
		freestart += slot1->pagecnt;
		freecount -= slot1->pagecnt;
		afterslot = slot1;
	    }
	}
	if (slot2 && slot2->pagecnt < freecount) {
	    moveblobto(xdb, slot2, afterslot, slot2->pagecnt);
	}
    }

    /* zero slot */
    memset(slot, 0, sizeof(*slot));
    slot->slotno = id;
    rpmxdbUpdateSlot(xdb, slot);

    /* enqueue into free chain */
    slot->next = xdb->firstfree;
    xdb->firstfree = slot->slotno;

    /* check if we can truncate the file */
    slot = xdb->slots + xdb->slots[xdb->nslots].prev;
    if (slot->startpage + slot->pagecnt < xdb->slots[xdb->nslots].startpage / 4 * 3) {
	/* truncate */
	unsigned int newend = slot->startpage + slot->pagecnt;
	unsigned char *newaddr;
	
        newaddr = mremap(xdb->mapped, xdb->mappedlen, newend * xdb->pagesize, MREMAP_MAYMOVE);
	if (newaddr != MAP_FAILED) {
	    xdb->mapped = newaddr;
	    xdb->mappedlen = newend * xdb->pagesize;
	    ftruncate(xdb->fd, newend * xdb->pagesize);
	    xdb->slots[xdb->nslots].startpage = newend;
	}
    }

    rpmpkgUnlock(xdb->pkgdb, 1);
    return RPMRC_OK;
}

int rpmxdbResizeBlob(rpmxdb xdb, unsigned int id, size_t newsize)
{
    struct xdb_slot *slot;
    unsigned int oldpagecnt, newpagecnt;
    if (!id)
	return RPMRC_FAIL;
    if (rpmpkgLock(xdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    newpagecnt = (newsize + xdb->pagesize - 1) / xdb->pagesize;
    if (newpagecnt == slot->pagecnt) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_OK;
    }
    if (newpagecnt <= xdb->slots[slot->next].startpage - slot->startpage) {
	/* can do it inplace */
	oldpagecnt = slot->pagecnt;
	if (newpagecnt > oldpagecnt) {
	    /* zero new pages */
	    if (rpmxdbWriteEmptyPages(xdb, slot->startpage + oldpagecnt, newpagecnt - oldpagecnt)) {
		rpmpkgUnlock(xdb->pkgdb, 1);
		return RPMRC_FAIL;
	    }
	}
	slot->pagecnt = newpagecnt;
	rpmxdbUpdateSlot(xdb, slot);
	xdb->usedblobpages -= oldpagecnt;
	xdb->usedblobpages += newpagecnt;
	if (!newpagecnt) {
	    /* remove from old chain */
	    slot->startpage = xdb->slotnpages;
	    xdb->slots[slot->prev].next = slot->next;
	    xdb->slots[slot->next].prev = slot->prev;
	    /* enqueue into head */
	    slot->prev = 0;
	    slot->next = xdb->slots[0].next;
	    xdb->slots[slot->next].prev = slot->slotno;
	    xdb->slots[0].next = slot->slotno;
	}

	if (!newpagecnt || !slot->remapcallback) {
	    if (slot->mapped)
		munmap(slot->mapped, oldpagecnt * xdb->pagesize);
	    slot->mapped = 0;
	} else if (newpagecnt != oldpagecnt) {
	    unsigned char *newaddr;
	    if (slot->mapped) {
		newaddr = mremap(slot->mapped, oldpagecnt * xdb->pagesize, newpagecnt * xdb->pagesize, MREMAP_MAYMOVE);
	    } else {
		newaddr = mmap(0, newpagecnt * xdb->pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, slot->startpage * xdb->pagesize);
	    }
	    if (newaddr == MAP_FAILED) {
		slot->pagecnt = oldpagecnt;
		rpmxdbUpdateSlot(xdb, slot);
		rpmpkgUnlock(xdb->pkgdb, 1);
		return RPMRC_FAIL;
	    }
	    slot->mapped = newaddr;
	}
	if (slot->remapcallback && newpagecnt != oldpagecnt)
	    slot->remapcallback(xdb, slot->remapcallbackdata, slot->mapped, newpagecnt * xdb->pagesize);
    } else {
	if (moveblob(xdb, slot, newpagecnt)) {
	    rpmpkgUnlock(xdb->pkgdb, 1);
	    return RPMRC_OK;
	}
    }
    rpmpkgUnlock(xdb->pkgdb, 1);
    return RPMRC_OK;
}

int rpmxdbMapBlob(rpmxdb xdb, unsigned int id, void (*remapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize), void *remapcallbackdata)
{
    struct xdb_slot *slot;
    if (!id || !remapcallback)
	return RPMRC_FAIL;
    if (rpmpkgLock(xdb->pkgdb, 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmpkgUnlock(xdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
    if (!slot->startpage || slot->mapped) {
	rpmpkgUnlock(xdb->pkgdb, 0);
        return RPMRC_FAIL;
    }
    if (slot->pagecnt) {
	slot->mapped = mmap(0, slot->pagecnt * xdb->pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, xdb->fd, slot->startpage * xdb->pagesize);
	if (slot->mapped == MAP_FAILED) {
	    slot->mapped = 0;
	    rpmpkgUnlock(xdb->pkgdb, 0);
	    return RPMRC_FAIL;
	}
    } else {
	slot->mapped = 0;
    }
    slot->remapcallback = remapcallback;
    slot->remapcallbackdata = remapcallbackdata;
    remapcallback(xdb, remapcallbackdata, slot->mapped, slot->mapped ? slot->pagecnt * xdb->pagesize : 0);
    rpmpkgUnlock(xdb->pkgdb, 0);
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
	munmap(slot->mapped, slot->pagecnt * xdb->pagesize);
	slot->mapped = 0;
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
    if (rpmpkgLock(xdb->pkgdb, 1))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    if (id >= xdb->nslots) {
	rpmpkgUnlock(xdb->pkgdb, 1);
        return RPMRC_FAIL;
    }
    slot = xdb->slots + id;
#if 0
    printf("rpmxdbRenameBlob #%d %d/%d -> %d/%d\n", id, slot->blobtag, slot->subtag, blobtag, subtag);
#endif
    if (!slot->startpage) {
	rpmpkgUnlock(xdb->pkgdb, 1);
	return RPMRC_FAIL;
    }
    if (slot->blobtag == blobtag && slot->subtag == subtag) {
	rpmpkgUnlock(xdb->pkgdb, 1);
	return RPMRC_OK;
    }
    if (rpmxdbFindBlob(xdb, &otherid, blobtag, subtag, 0)) {
	rpmpkgUnlock(xdb->pkgdb, 1);
	return RPMRC_FAIL;
    }
    if (otherid) {
#if 0
	printf("(replacing #%d)\n", otherid);
#endif
	if (rpmxdbDeleteBlob(xdb, otherid)) {
	    rpmpkgUnlock(xdb->pkgdb, 1);
	    return RPMRC_FAIL;
	}
    }
    slot = xdb->slots + id;
    slot->blobtag = blobtag;
    slot->subtag = subtag;
    rpmxdbUpdateSlot(xdb, slot);
    rpmpkgUnlock(xdb->pkgdb, 1);
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

    if (rpmpkgLock(xdb->pkgdb, 0))
        return RPMRC_FAIL;
    if (rpmxdbReadHeader(xdb)) {
	rpmpkgUnlock(xdb->pkgdb, 0);
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
    rpmpkgUnlock(xdb->pkgdb, 0);
    return RPMRC_OK;
}

