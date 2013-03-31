#define SIGLENGTH 8
#define CHUNK 1024

void recursedir(char*,void (*)(const char*));
void dumpFile(const char*);
char* mapSignatures(const char*);
void scanFile(const char* filename);
