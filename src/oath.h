/*
 * File:   oath.h
 * Author: mitya
 *
 * Created on September 25, 2011, 5:25 AM
 */

#ifndef OATH_H
#define	OATH_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <slapi-plugin.h>

typedef struct _Token {
    char *serial;
    long counter;
    struct berval *seed;
    char *pin;
} Token;

typedef struct _OATHConfig {
    int hotp_length;
    int hotp_trunc_offset;
    int hotp_checksum;
    int hotp_inner_window;
    int hotp_outer_window;
    char *token_base;
} OATHConfig;

int oath_config(OATHConfig *config, char *dn, Slapi_ComponentId *plugin_id);
Token *oath_token_from_entry(Token *token, Slapi_Entry *entry);
OATHConfig *oath_config_from_entry(OATHConfig *config, Slapi_Entry *entry);
void oath_token_free(Token *token);
void oath_config_free(OATHConfig *config);

/*
 * This function generates an OATH HOTP (RFC 4226) compliant one-time password.
 *
 * @param hotp: Pointer to memory area where the resulting OTP will be stored.
 * It should be allocated by the caller.
 *
 * @param hotp_len: Length of the resulting OTP.
 *
 * @param seed: Pointer to binary representation of seed.
 *
 * @param seed_len: Seed length.
 *
 * @param counter: Counter value.
 *
 * @param trunc_offset: Truncation offset.
 *
 * @param checksum: Whether to append checksum.
 *
 * @return Pointer to the resulting OTP string.
 *
 */
unsigned char *oath_hotp(unsigned char *hotp, int hotp_len, const char *seed, int seed_len, long counter, int trunc_offset, int checksum);

#ifdef	__cplusplus
}
#endif

#endif	/* OATH_H */

