#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include "dirent.h"
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <string.h>

#define CHUNK 1024

void recursedir(char*,void (*)(const char*));
void dumpFile(const char*);

int main(int argc, char **argv){
    if (argc < 2)
        return 1;
    recursedir(argv[1],&puts);
    return 0;
}

void recursedir(char *path, void (*doOnFile)(const char*)){
    DIR *curdir;
    struct dirent *ent;
    char nextpath[1024] = "";
    if ((curdir = opendir(path)) == NULL)
        return;

    while((ent = readdir(curdir)) != NULL) {
        strcpy(nextpath,path);
        strcat(nextpath,"/"); 
        strcat(nextpath,ent->d_name);
        if (ent->d_type == DT_DIR &&
        strcmp(".",ent->d_name) != 0 &&
        strcmp("..",ent->d_name) != 0) {
            recursedir(nextpath,doOnFile);
        }
        if (ent->d_type == DT_REG){
            printf("Dumping file '%s':\n",nextpath);
            doOnFile(nextpath);
        }
    }
}

void dumpFile(const char *filename){
    char buffer[CHUNK];
    FILE *file;
    size_t nread;
    file = fopen(filename,"r");
    if (file){
        while ((nread = fread(buffer, 1, sizeof buffer, file)) > 0) {
            fwrite(buffer ,1, nread, stdout);
        }
        if (ferror(file)) {
            printf("Error\n");
        }
        fclose(file);
    }
}
