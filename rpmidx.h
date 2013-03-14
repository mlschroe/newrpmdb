#include "rpmpkg.h"

struct rpmidxdb_s;
typedef struct rpmidxdb_s *rpmidxdb;

int rpmidxOpen(rpmidxdb *idxdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode);
void rpmidxClose(rpmidxdb idxdbp);

int rpmidxGet(rpmidxdb idxdb, char *key, unsigned int **pkgidxlist, unsigned int *pkgidxnum);
int rpmidxPut(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys);
int rpmidxErase(rpmidxdb idxdb, unsigned int pkgidx, char **keys, unsigned int nkeys);
int rpmidxList(rpmidxdb idxdb, char ***keylistp, unsigned int *nkeylistp);
