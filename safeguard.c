#ifdef _WIN32
#include "dirent.h"
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char* fileptr;
    buf = (struct stat* )malloc(sizeof(struct stat));
    if (fp == NULL){
        fputs("Unable to open signature file\n",stderr);
        return NULL;
    }
    stat(fileLoc,buf);
    fileptr = memorymap(fp,buf->st_size);
    fclose(fp);
    //free(fileptr);
    free(buf);
    return fileptr;
}

void scanFile(const char* filename){
    struct stat *buf = (struct stat* )malloc(sizeof(struct stat));
    int sigcount,i,j,p;
    int virusDetected = FALSE;
    char needle[SIGLENGTH];
    char* signatures = mapSignatures(sigFile);
	FILE *fp;
	char* fileptr;
    if (signatures == NULL){
        fputs("Missing signature file?",stderr);
        return;
    }
    stat(sigFile,buf);
    sigcount = ((int)buf->st_size)/SIGLENGTH;

    fp = fopen(filename,"rb");
    if (fp == NULL){
        fprintf(stderr,"Unable to open file to scan: %s\n",filename);
        return;
    }
    stat(filename,buf);
    fileptr = memorymap(fp,buf->st_size);
    fclose(fp);
    for (i = 0; i < sigcount; i++){
        for (j = 0; j < SIGLENGTH; j++){
            needle[j] = signatures[(i*SIGLENGTH)+j];
        }
        p = searchmem(fileptr,buf->st_size,needle,(size_t)SIGLENGTH);
        if (p == TRUE){
            virusDetected = TRUE;
        }
    }
    if (virusDetected == TRUE){
        printf("Virus detected! File: %s\n",filename);
    }
    free(fileptr);
    free(buf);
}

int searchmem(char* haystack, size_t haystackLength, char* needle, size_t needleLength){
    char* curpos = haystack;
    char* lastpos = haystack + haystackLength - needleLength;
	unsigned int i;
    //if needle length is 0, technically it is present.
    if (needleLength == 0){
        return TRUE;
    }
    if (haystackLength < needleLength){
        return FALSE;
    }
    while (curpos < lastpos){
        if (!memcmp(curpos,needle,needleLength)){
			// following commented block is pretty good for checking false positives
			/*
			for (i = 0; i < needleLength; i++){
				putchar(curpos[i]);
			}
			putchar('\n');
			for (i = 0; i < needleLength; i++){
				putchar(needle[i]);
			}
			putchar('\n');
			//*/
            return TRUE;
        }
		curpos++;
    }
    return FALSE;
}

char* memorymap(FILE *fp, size_t fileSize){
    char* location = (char*)malloc(fileSize);
    fread(location, sizeof(char), (int)fileSize,fp);
    return location;
}

void recursedir(char *path, void (*doOnFile)(const char*)){
    DIR *curdir;
    struct dirent *ent;
    char nextpath[CHUNK] = "";
    struct stat *buf;
    buf = (struct stat*)malloc(sizeof(struct stat));

    if ((curdir = opendir(path)) == NULL)
        return;

    while((ent = readdir(curdir)) != NULL) {
        strcpy(nextpath,path);
        strcat(nextpath,"/"); 
        strcat(nextpath,ent->d_name);
        stat(nextpath,buf);
        if (S_ISDIR(buf->st_mode) &&
        strcmp(".",ent->d_name) != 0 &&
        strcmp("..",ent->d_name) != 0) {
            recursedir(nextpath,doOnFile);
        }
        if (S_ISREG(buf->st_mode)){
            fprintf(stderr,"Checking %s...\n",ent->d_name);
            doOnFile(nextpath);
        }
    }
    free(buf);
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
