#include "rpmpkg.h"
#include "rpmxdb.h"

struct rpmidxdb_s;
typedef struct rpmidxdb_s *rpmidxdb;

int rpmidxOpen(rpmidxdb *idxdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode);
int rpmidxOpenXdb(rpmidxdb *idxdbp, rpmpkgdb pkgdb, rpmxdb xdb, unsigned int xdbtag);
void rpmidxClose(rpmidxdb idxdbp);

int rpmidxGet(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int **pkgidxlist, unsigned int *pkgidxnum);
int rpmidxPut(rpmidxdb idxdb, unsigned int pkgidx, const unsigned char *key, unsigned int keyl, unsigned int datidx);
int rpmidxErase(rpmidxdb idxdb, unsigned int pkgidx, const unsigned char *key, unsigned int keyl, unsigned int datidx);
int rpmidxPutStrings(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys);
int rpmidxEraseStrings(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys);
int rpmidxList(rpmidxdb idxdb, unsigned int **keylistp, unsigned int *nkeylistp, unsigned char **datap);

int rpmidxUpdateGeneration(rpmidxdb idxdb);
int rpmidxStats(rpmidxdb idxdb);

