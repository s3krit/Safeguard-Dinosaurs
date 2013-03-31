#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include "dirent.h"
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "safeguard.h"

char* sigFile;

int main(int argc, char **argv){
    if (argc < 3)
        exit(EXIT_FAILURE);
    sigFile = argv[1];
    recursedir(argv[2],&scanFile);
    exit(EXIT_SUCCESS);
}

char* mapSignatures(const char* fileLoc){
    FILE *fp = fopen(fileLoc,"rb");
    struct stat *buf;
    buf = malloc(sizeof(struct stat));
    if (fp == NULL){
        fputs("Unable to open signature file\n",stderr);
        return NULL;
    }
    stat(fileLoc,buf);
    char* fileptr = mmap(NULL, buf->st_size, PROT_READ, MAP_SHARED, fileno(fp), 0);
    fclose(fp);
    free(buf);
    return fileptr;
}

void scanFile(const char* filename){
    struct stat *buf = malloc(sizeof(struct stat));
    int sigcount,i,j;
    char needle[SIGLENGTH];
    char* signatures = mapSignatures(sigFile);
    if (signatures == NULL){
        fputs("Missing signature file?",stderr);
        return;
    }
    FILE *fp = fopen(filename,"rb");
    fclose(fp);
    stat(sigFile,buf);
    sigcount = ((int)buf->st_size)/SIGLENGTH;
    for (i = 0; i < sigcount; i++){
        for (j = 0; j < SIGLENGTH; j++){
            needle[j] = signatures[(i*SIGLENGTH)+j];
        }
        char *p = memmem(signatures,buf->st_size,needle,(size_t)SIGLENGTH);
        if (p == NULL){
            puts("Virus detected!");
        } else {
            puts("File safe!");
        }
    }
}

void recursedir(char *path, void (*doOnFile)(const char*)){
    DIR *curdir;
    struct dirent *ent;
    char nextpath[CHUNK] = "";
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

void dumpFile(const char *fileLoc){
    char buffer[CHUNK];
    FILE *fd;
    size_t nread;
    fd = fopen(fileLoc,"r");
    if (fd){
        while ((nread = fread(buffer, 1, sizeof buffer, fd)) > 0) {
            fwrite(buffer ,1, nread, stdout);
        }
        if (ferror(fd)) {
            printf("Error\n");
        }
        fclose(fd);
    }
}
