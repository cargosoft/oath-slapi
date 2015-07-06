#include <openssl/hmac.h>
#include <stdio.h>

#include "oath.h"

#define HMAC_SHA1_SIZE 20

static int DIGITS_POWER[]
        // 0  1   2    3     4      5       6        7         8
        = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

static int DOUBLE_DIGITS[] = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

int oath_checksum(long num, int digits) {

    int double_digit = 1;
    int total = 0;

    while (0 < digits--) {
        int digit = (int) (num % 10);
        num /= 10;
        if (double_digit) {
            digit = DOUBLE_DIGITS[digit];
        }
        total += digit;
        double_digit = !double_digit;
    }

    int result = total % 10;

    if (result > 0) {
        result = 10 - result;
    }

    return result;

}

unsigned char *oath_hotp(unsigned char *hotp, int hotp_len, const char *seed, int seed_len, long counter, int trunc_offset, int checksum) {

    if (!hotp || hotp_len <= 0 || hotp_len > 8 || 
        !seed || seed_len <=0 || 
        counter < 0 || trunc_offset > HMAC_SHA1_SIZE - 4)
        return NULL;

    unsigned char hash[HMAC_SHA1_SIZE];
    unsigned int hash_len;
    unsigned char text[8];
    char format[5];
    int i;

    for (i = 7; i >= 0; i--) {
        text[i] = counter & 0xFF;
        counter >>= 8;
    }

    if (HMAC(EVP_sha1(), seed, seed_len, text, 8, hash, &hash_len) && hash_len == HMAC_SHA1_SIZE) {

        int offset = (trunc_offset >= 0 ? trunc_offset : hash[HMAC_SHA1_SIZE - 1] & 0xF);

        int binary = ((hash[offset] & 0x7F) << 24) |
                       ((hash[offset + 1] & 0xFF) << 16) |
                       ((hash[offset + 2] & 0xFF) << 8) |
                       (hash[offset + 3] & 0xFF);

        int otp = binary % DIGITS_POWER[hotp_len];

        if (checksum) otp = 10 * otp + oath_checksum(otp, hotp_len);

        snprintf(format, 5, "%%0%dd", hotp_len);
        snprintf(hotp, checksum ? hotp_len + 2 : hotp_len + 1, format, otp);

        return hotp;

    } else
        return NULL;

}
