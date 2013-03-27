#include "rpmpkg.h"

struct rpmxdb_s;
typedef struct rpmxdb_s *rpmxdb;

int rpmxdbOpen(rpmxdb *xdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode);
void rpmxdbClose(rpmxdb xdb);
int rpmxdbFindBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag, int create);
int rpmxdbDeleteBlob(rpmxdb xdb, unsigned int id) ;
int rpmxdbMapBlob(rpmxdb xdb, unsigned int id, void (*remapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize), void *remapcallbackdata);
int rpmxdbUnmapBlob(rpmxdb xdb, unsigned int id);
int rpmxdbResizeBlob(rpmxdb xdb, unsigned int id, size_t newsize);
int rpmxdbFsyncBlob(rpmxdb xdb, unsigned int id);
int rpmxdbRenameBlob(rpmxdb xdb, unsigned int id, unsigned int blobtag, unsigned int subtag);
void rpmxdbSetFsync(rpmxdb xdb, int dofsync);
int rpmxdbStats(rpmxdb xdb);


