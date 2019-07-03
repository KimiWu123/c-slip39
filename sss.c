
// #include <endian.h>
// #include <stdbool.h>
#include "pbkdf2.h"
#include "hmac.h"
#include "sss.h"


void create_digest(uint8_t* random_data, uint16_t random_data_len, 
                    uint8_t* shared_secret, uint16_t shared_secret_len,
                    _out uint8_t* out)
{
    uint8_t mac[32];
    hmac_sha256(random_data, random_data_len, shared_secret, shared_secret_len, mac);
    memcpy(out, mac, DIGEST_LENGTH_BYTES);
}


static uint16_t EXP_TABLE[255] = {0};
static uint16_t LOG_TABLE[256] = {0};
void _precompute_exp_log()  __attribute__((constructor));
void _precompute_exp_log()
{
    uint16_t poly = 1;
    for(uint16_t i=0; i<255; i++) {
        EXP_TABLE[i] = poly;
        LOG_TABLE[poly] = i;

        poly = (poly<<1) ^ poly;

        if(poly & 0x100)
            poly ^= 0x11B;
    }
}

void interpolate(share_with_x* shares, uint16_t shares_len, 
                  uint16_t a_share_len, uint8_t x, _out uint8_t* out)
{
    uint8_t* x_coord = malloc(shares_len);
    for(uint16_t i=0; i<shares_len; i++) {
        x_coord[i] = shares[i].x;
    }

    for(uint16_t i=0; i<shares_len; i++) {
        if(x == x_coord[i]) {
            memcpy(out, shares[i].share, a_share_len);
            return;
        }
    }

    uint16_t log_prod=0;
    for(uint16_t i=0; i<shares_len; i++) {
        log_prod += LOG_TABLE[shares[i].x ^ x];
    }
    // dlog("log_prod: %d", log_prod);

    for(uint16_t i=0; i<shares_len; i++) {
        uint16_t sum=0;
        for(uint16_t j=0; j<shares_len; j++) {
            sum += LOG_TABLE[shares[i].x ^ shares[j].x];
        }
        int16_t log_basis_eval = (log_prod - LOG_TABLE[shares[i].x ^ x] - sum)%255;
        if(log_basis_eval < 0) {
            log_basis_eval += 255;
        }
        // dlog("log_basis_eval %d / LOG:%d, share_x^x:%d, sum:%d", 
        //     log_basis_eval, LOG_TABLE[shares[i].x ^ x], shares[i].x^x, sum);

        uint8_t* intermediate_sum = malloc(a_share_len);
        memzero(intermediate_sum, a_share_len);
        for(uint16_t k=0; k<a_share_len; k++) {
            uint8_t share_val = shares[i].share[k];
            intermediate_sum[k] = out[k];
            if(share_val != 0)
                intermediate_sum[k] ^= EXP_TABLE[(LOG_TABLE[share_val]+log_basis_eval)%255];
            else 
                intermediate_sum[k] ^= 0;
        }
        memcpy(out, intermediate_sum, a_share_len);
        memzero(intermediate_sum, a_share_len); free(intermediate_sum);
    }
    memzero(x_coord, shares_len); free(x_coord);
}