/* Joern derin analiz fikstürü (C): beklenen bulgular satır sonunda EXPECT ile işaretli. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void run(const char *name) {
    char cmd[256];
    strcpy(cmd, "convert ");
    strcat(cmd, name);  /* EXPECT: overflow */
    system(cmd);  /* EXPECT: command */
}

static void run_fixed(void) {
    system("ls -l");
}

int main(int argc, char **argv) {
    char buf[64];
    char *home = getenv("HOME");
    if (argc > 2) {
        run(argv[1]);
        strcpy(buf, argv[2]);  /* EXPECT: overflow */
        FILE *f = fopen(argv[2], "r");  /* EXPECT: path */
        if (f) fclose(f);
    }
    run_fixed();
    printf(home);  /* EXPECT: format */
    printf("%s\n", home);
    strcpy(buf, "sabit");
    return 0;
}
