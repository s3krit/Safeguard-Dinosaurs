#define SIGLENGTH 8
#define CHUNK 1024
#define TRUE 1
#define FALSE 0

void recursedir(char*,void (*)(const char*));
void dumpFile(const char*);
char* mapSignatures(const char*);
void scanFile(const char* filename);
int searchmem(char*, size_t, char*, size_t);
char* memorymap(FILE*, size_t);
