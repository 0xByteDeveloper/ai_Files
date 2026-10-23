/* deneme.c — mp_encoder sozdizimi demo programi
 * Iki ayri fonksiyon: SecretHash + main
 * Amac: kullanici komutu "mp_encoder.exe deneme.exe denemeoutput.exe m2 start end"
 * ile gercek bir dosyayi sifreleyip sonucun canli calistigini gostermek.
 */
#include <stdio.h>
#include <stdint.h>

static volatile uint32_t g_sink = 0;

/* Korunacak fonksiyon 1: kucuk bir hash karisimcisi */
uint32_t SecretHash(uint32_t x, uint32_t rounds)
{
    uint32_t h = 0x9E3779B9u ^ x;
    for (uint32_t i = 0; i < rounds; i++) {
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h << 5;
        h += x + i * 0x85EBCA6Bu;
        h = (h << 7) | (h >> 25);
    }
    return h;
}

int main(void)
{
    printf("deneme.exe basladi\n");
    uint32_t acc = 0;
    for (uint32_t r = 1; r <= 40; r++) {
        acc ^= SecretHash(r * 0x1234567u, 8);
    }
    g_sink = acc;
    printf("hash=%08X sink=%u bitti\n", acc, g_sink);
    return 0;
}
