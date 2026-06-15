#include <stdio.h>

int main(void) {
    char c;
    printf("1文字入力してください: ");
    scanf("%c", &c);
    printf("ASCII コード: %d\n", (int)c);
    return 0;
}