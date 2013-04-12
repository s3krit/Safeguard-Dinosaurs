#define SIGLENGTH 8
#define CHUNK 2048
#define TRUE 1
#define FALSE 0
#ifdef _WIN32
#include "dirent.h"
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void recursedir(char*,void (*)(const char*));
void dumpFile(const char*);
char* mapSignatures(const char*);
void scanFile(const char* filename);
int searchmem(char*, size_t, char*, size_t);
char* memorymap(FILE*, size_t);
char* strAppend(char*, const char*);
int isExecutable(const char*);
