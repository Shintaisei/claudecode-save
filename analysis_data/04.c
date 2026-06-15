#include <stdio.h>
#include <string.h>

int main(void) {
    char s[128];
    int count[256] = {0};
    int len;
    int max;
    int i, j;

    /* fgets で空白を含む文字列を受け取る */
    printf("文字列を入力してください: ");
    fgets(s, 128, stdin);

    /* 改行文字を終端文字に置き換える */
    if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = '\0';

    len = strlen(s);

    /* 各文字の出現回数をカウント */
    for (i = 0; i < len; i++) {
        count[(int)s[i]]++;
    }

    /* アルファベットが含まれているか確認 */
    max = 0;
    for (i = 'A'; i <= 'z'; i++) {
        if (i > 'Z' && i < 'a') continue;
        if (count[i] > max) {
            max = count[i];
        }
    }

    if (max == 0) {
        printf("none\n");
        return 0;
    }

    /* 出現回数の多い順に出力（バブルソートの考え方で回数ごとに処理） */
    /* max から 1 まで順番に、その回数のアルファベットをASCII順に出力 */
    for (j = max; j >= 1; j--) {
        for (i = 'A'; i <= 'z'; i++) {
            if (i > 'Z' && i < 'a') continue;
            if (count[i] == j) {
                printf("%c %d\n", (char)i, j);
            }
        }
    }

    return 0;
}