#include "safeguard.h"

char* sigFile;
int virusCount;
char* summary;
char* signatures;
int sigcount;
int scanned = 0;

int main(int argc, char **argv){
    int i;
    struct stat *buf = (struct stat* )malloc(sizeof(struct stat));
    // This is kinda bad, should maybe be dynamically allocated
    summary = (char*)malloc(sizeof(char)*10000);
    virusCount = 0;

    if (argc < 3)
        exit(EXIT_FAILURE);

    sigFile = argv[1];
    // Load signatures file, and count the amount of signatures.
    signatures = mapSignatures(sigFile);
    if (signatures == NULL){
        fputs("Missing signature file?",stderr);
        exit(EXIT_SUCCESS);
    }
    lstat(sigFile,buf);
    sigcount = ((int)buf->st_size)/SIGLENGTH;
    free(buf);

    recursedir(argv[2],&scanFile);
    for(i = 0; i < 20; i++){
        printf("=");
    }
    puts("");
    puts("Scan summary:");
    printf("%d viruses detected.\n",virusCount);
    printf("%s",summary);
    exit(EXIT_SUCCESS);
}

char* strAppend(char* str1, const char* str2) {
    str1 = realloc(str1, (strlen(str1) + strlen(str2) + 50) * sizeof(char));
    strcat(str1, str2);
    return str1;
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
    lstat(fileLoc,buf);
    fileptr = memorymap(fp,buf->st_size);
    fclose(fp);
    free(buf);
    return fileptr;
}

void scanFile(const char* filename){
    struct stat *buf = (struct stat* )malloc(sizeof(struct stat));
    int i,j,p;
    int virusDetected = FALSE;
    char needle[SIGLENGTH];
	FILE *fp;
	char* fileptr;
    scanned++;
    fp = fopen(filename,"rb");
    if (fp == NULL){
        fprintf(stderr,"Unable to open file to scan: %s. Scanned: %d\n",filename,scanned);
        //return;
    }

    // perform checks as to whether file is worth scanning

    if(!isExecutable(filename)){
        puts("Not executable");
        return;
    }

    lstat(filename,buf);
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
        virusCount++;
        strcat(summary, "Virus detected at: ");
        strcat(summary, filename);
        strcat(summary, "\n");
        printf("Virus detected! File: %s\n",filename);
    }
    
    // post-scan cleanup

    free(fileptr);
    free(buf);
}

int isExecutable(const char* filename){
    // elf and pe are signatures for ELF executables and Windows Portable Executables, respectively.
    char elf[4] = {0x7f, 0x45, 0x4c, 0x46}; // '.ELF' at start of file
    char pe[4] = {0x4d, 0x5a, 0x40, 0x00}; // 'MZ@.' at start of file
    char fileheader[4] = {0};
    int i;

   FILE *fp = fopen(filename,"rb");

   // if we can't read it, why try and scan it?
   if (fp == NULL){
       return FALSE;
   }

   for (i = 0; i <= 4; i++){
       fileheader[i] = getc(fp);
   }

   if (memcmp(fileheader,elf,4) == 0 || memcmp(fileheader,pe,4) == 0){
       return TRUE;
   }
    return FALSE;
}

int searchmem(char* haystack, size_t haystackLength, char* needle, size_t needleLength){
    char* curpos = haystack;
    char* lastpos = haystack + haystackLength - needleLength;
    //if needle length is 0, technically it is present.
    if (needleLength == 0){
        return TRUE;
    }
    if (haystackLength < needleLength){
        return FALSE;
    }
    while (curpos < lastpos){
        if (!memcmp(curpos,needle,needleLength)){
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

        // Must use lstat here or it will reach symlinks and cry
        lstat(nextpath,buf);
        if (S_ISDIR(buf->st_mode) &&
        strcmp(".",ent->d_name) != 0 &&
        strcmp("..",ent->d_name) != 0) {
            recursedir(nextpath,doOnFile);
        }
        if (S_ISREG(buf->st_mode) && strcmp(ent->d_name,sigFile)){
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
