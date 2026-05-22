#include <stdio.h>

int main() {
    int a = 20;
    for (int i = 0; i < 10; i++) {
        a += i << 2;
    }
    printf("%d\n", a);
    return 0;
}
