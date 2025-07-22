/*
extern int sqlite_main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    return sqlite_main(argc, argv);
}
*/
#include <uk/config.h>
#include <uk/bits/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <time.h>
#include <sys/io.h>

#include <uk/plat/bootstrap.h>

#ifndef DB_NAME
#define DB_NAME     "/ssb.sqlite"
#endif

sqlite3 *db;

static int callback(
        void *unused __attribute__((unused)),
        int argc, char **argv, char **azColName) {
    return 0;
}

int main(int argc, char **argv){
  outb(0xf4, 0xFE);
	printf("Startup trace (nsec): main begin: %lu\n", ukplat_monotonic_clock());
  char *zErrMsg = 0;
  int rc;

    rc = sqlite3_open(DB_NAME, &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return(1);
    }
    
    printf("query file: %s\n", getenv("QUERYFILE"));
    FILE *file = fopen(getenv("QUERYFILE"), "r");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* query = (char*)malloc(file_size * sizeof(char));

    fread(query, 1, file_size, file);
    fclose(file);

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) {
        perror("Could not read start time!");
        sqlite3_close(db);
        return 1;
    }

    rc = sqlite3_exec(db, query, callback, 0, &zErrMsg);
    
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC, &end)) {
        perror("Could not read start time!");
        sqlite3_close(db);
        return 1;
    }

    time_t n_sec = end.tv_sec - start.tv_sec;
    long n_nsec = end.tv_nsec - start.tv_nsec;
    if (n_nsec < 0) {
        --n_sec;
        n_nsec += 1000000000L;
    }
    printf("Run Time: %ld.%09ld\n", n_sec, n_nsec);
    
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return 1;
    }

    sqlite3_close(db);

    // Ensure output is printed and VM really quits
    fflush(stdout);
    ukplat_halt();
    return 0;
}
