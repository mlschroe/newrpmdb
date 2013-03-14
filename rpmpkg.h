struct rpmpkgdb_s;
typedef struct rpmpkgdb_s *rpmpkgdb;

int rpmpkgOpen(rpmpkgdb *pkgdbp, const char *filename, int flags, int mode);
void rpmpkgClose(rpmpkgdb pkgdbp);
void rpmpkgSetFsync(rpmpkgdb pkgdbp, int dofsync);
int rpmpkgGet(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char **blobp, unsigned int *bloblp);
int rpmpkgPut(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char *blob, unsigned int blobl);
int rpmpkgErase(rpmpkgdb pkgdb, unsigned int pkgidx);

int rpmpkgList(rpmpkgdb pkgdb, unsigned int **pkgidxlistp, unsigned int *npkgidxlistp);
int rpmpkgLock(rpmpkgdb pkgdb, int excl);
int rpmpkgUnlock(rpmpkgdb pkgdb, int excl);

int rpmpkgGetLZO(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char **blobp, unsigned int *bloblp);
int rpmpkgPutLZO(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char *blob, unsigned int blobl);

