#include <stdio.h>
#include <string.h>

int main(void) {
    char s[65];
    char c;
    int pos = -1;
    int len;

    /* fgets で空白を含む文字列を受け取る（資料 p.2/2 の方法） */
    printf("文字列を入力してください: ");
    fgets(s, 65, stdin);

    /* 改行文字を終端文字に置き換える（資料の注意事項より） */
    if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = '\0';

    len = strlen(s);

    /* getchar で1文字受け取る（資料 p.1/2 の方法） */
    printf("検索する文字を入力してください: ");
    c = getchar();

    /* 末尾から最初に一致した位置を探す → 最後の出現位置 */
    for (int i = 0; i < len; i++) {
        if (s[i] == c) {
            pos = i + 1; /* 1文字目から数えるので +1 */
        }
    }

    if (pos == -1) {
        printf("not exist\n");
    } else {
        printf("%d文字目\n", pos);
    }

    return 0;
}