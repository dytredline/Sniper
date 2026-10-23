#include <stdlib.h>

int main(void) {
    int *item = malloc(sizeof(int));
    if (item == NULL) return 2;
    *item = 7;
    free(item);
    return *item;
}
