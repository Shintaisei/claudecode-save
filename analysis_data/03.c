#include <stdio.h>
#include <string.h>

int main(void) {
    char s[128];
    int count[256] = {0}; /* ASCIIコードの種類数(256)と同じサイズの配列 */
    int len;
    int max;
    int result;
    int i;

    /* fgets で空白を含む文字列を受け取る */
    printf("文字列を入力してください: ");
    fgets(s, 128, stdin);

    /* 改行文字を終端文字に置き換える */
    if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = '\0';

    len = strlen(s);

    /* 各文字の出現回数をカウント */
    for (i = 0; i < len; i++) {
        count[(int)s[i]]++; /* s[i]のASCIIコードを添え字にして出現回数を記録 */
    }

    /* アルファベットの中で最大出現回数を探す */
    max = 0;
    for (i = 'A'; i <= 'z'; i++) { /* 'A'(65) から 'z'(122) の範囲 */
        /* アルファベット以外('Z'と'a'の間)を除外 */
        if (i > 'Z' && i < 'a') continue;
        if (count[i] > max) {
            max = count[i];
        }
    }

    /* アルファベットが1つも含まれていない場合 */
    if (max == 0) {
        printf("none\n");
        return 0;
    }

    /* 最大出現回数のうちASCIIコードが最も若いアルファベットを探す */
    result = -1;
    for (i = 'A'; i <= 'z'; i++) {
        if (i > 'Z' && i < 'a') continue;
        if (count[i] == max) {
            result = i; /* 最初に見つかったものが一番ASCIIコードが若い */
            break;
        }
    }

    printf("%c\n", (char)result);

    return 0;
}