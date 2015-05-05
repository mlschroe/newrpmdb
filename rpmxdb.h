#include "rpmpkg.h"

struct rpmxdb_s;
typedef struct rpmxdb_s *rpmxdb;

int rpmxdbOpen(rpmxdb *xdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode);
void rpmxdbClose(rpmxdb xdb);
void rpmxdbSetFsync(rpmxdb xdb, int dofsync);
int rpmxdbIsRdonly(rpmxdb xdb);

int rpmxdbLock(rpmxdb xdb, int excl);
int rpmxdbUnlock(rpmxdb xdb, int excl);

int rpmxdbFindBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag, int flags);
int rpmxdbDelBlob(rpmxdb xdb, unsigned int id) ;

int rpmxdbMapBlob(rpmxdb xdb, unsigned int id, void (*remapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize), void *remapcallbackdata);
int rpmxdbUnmapBlob(rpmxdb xdb, unsigned int id);

int rpmxdbResizeBlob(rpmxdb xdb, unsigned int id, size_t newsize);
int rpmxdbRenameBlob(rpmxdb xdb, unsigned int id, unsigned int blobtag, unsigned int subtag);

int rpmxdbSetUserGeneration(rpmxdb xdb, unsigned int usergeneration);
int rpmxdbGetUserGeneration(rpmxdb xdb, unsigned int *usergenerationp);

int rpmxdbStats(rpmxdb xdb);

/* flags for rpmxdbFindBlob */
#define RPMXDB_CREAT	(1 << 1)
#define RPMXDB_TRUNC	(1 << 2)

