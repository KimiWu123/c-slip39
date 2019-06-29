#ifndef __SLIP39_H__
#define __SLIP39_H__

#include <stdint.h>
#include "common_def.h"
#include "error_code.h"

int generate_mnemonic_shares(uint8_t* master_secret, uint16_t ms_len,
                              uint8_t* passphrase, uint16_t pp_len,
                              uint8_t group_threshold,
                              member_threshold* groups, uint8_t group_len,
                              uint8_t iter_exponent, 
                              _out mnemonic_string** mnemonic_shares);

int combin_mnemonics(mnemonic_string** mnemonic_shares, uint8_t mnemonic_count, 
                     uint8_t mnemonic_len, uint8_t* passphrase, uint8_t pp_len, 
                     _out uint8_t* ms);
int decode_mnemonic(mnemonic_string* mnemonic_str, uint8_t mnemonic_len, _out share_format* share);

#endif