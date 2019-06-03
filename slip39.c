
#include <endian.h>
#include "pbkdf2.h"
#include "hmac.h"
#include "slip39_English.h"
#include "slip39.h"
#include "util.h"


// RS-1024
uint32_t rs1024_polymod(uint16_t* value, uint8_t value_len)
{
    const static uint32_t GEN[] = {
        0xE0E040,
        0x1C1C080,
        0x3838100,
        0x7070200,
        0xE0E0009,
        0x1C0C2412,
        0x38086C24,
        0x3090FC48,
        0x21B1F890,
        0x3F3F120
    };

    uint32_t chk = 1;
    for(uint16_t i =0; i<value_len; i++){
        uint16_t v = value[i];
        // printf("%x, ", v);
        uint32_t b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ v;
        for(uint8_t j=0; j<10; j ++) {
            if((b >> j) & 1)
                chk ^= GEN[j];
            else 
                chk ^= 0;
        }
    }
    return chk;
}

uint32_t _rs1024_create_checksum(uint16_t* data, uint8_t data_len, _out uint16_t* out)
{
    uint8_t values_len = strlen(CUSTOMIZATION_STRING) + data_len + CHECKSUM_LENGTH_WORDS;
    uint16_t* values = malloc(values_len*sizeof(uint16_t));
    memzero(values, values_len*sizeof(uint16_t));

    for(uint8_t i=0; i<strlen(CUSTOMIZATION_STRING); i++) {
        values[i] = CUSTOMIZATION_STRING[i];
    }
    for(uint8_t i=0; i<data_len; i++){
        values[i+strlen(CUSTOMIZATION_STRING)] = data[i];
    }

    uint32_t checksum = rs1024_polymod(values, values_len) ^ 1;
    for(int8_t i=CHECKSUM_LENGTH_WORDS; i>0; i--){
        out[CHECKSUM_LENGTH_WORDS-i] = (checksum >> 10*(i-1)) & 1023;
    }
    memzero(values, values_len); free(values);
    return checksum;
}

uint8_t rs1024_verify_checksum(uint16_t* data, uint8_t data_len)
{
    uint8_t values_len = strlen(CUSTOMIZATION_STRING) + data_len;
    uint16_t* values = malloc(values_len*sizeof(uint16_t));
    memzero(values, values_len*sizeof(uint16_t));

    for(uint8_t i=0; i<strlen(CUSTOMIZATION_STRING); i++) {
        values[i] = CUSTOMIZATION_STRING[i];
    }
    for(uint8_t i=0; i<data_len; i++){
        values[i+strlen(CUSTOMIZATION_STRING)] = data[i];
    }
    uint8_t ret = rs1024_polymod(values, values_len) == 1;

    memzero(values, values_len*sizeof(uint16_t)); free(values);
    return ret;
}


void _xor(uint8_t* a, uint8_t* b, uint8_t len, _out uint8_t* out)
{
    for(uint8_t i=0; i<len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void _round_function(uint8_t i, uint8_t* passphrase, uint8_t iter_exponent, 
                    uint8_t* salt, uint8_t salt_len,
                    uint8_t* r, uint8_t r_len, _out uint8_t* out)
{
    uint8_t pass[65]={0};
    pass[0] = i;
    memcpy(&pass[1], passphrase, strlen(passphrase));

    uint8_t salt_r_len = r_len + salt_len;
    uint8_t* salt_r = malloc(salt_r_len);
    memzero(salt_r, salt_r_len);
    memcpy(salt_r, salt, salt_len);
    memcpy(salt_r + salt_len, r, r_len);

    pbkdf2_hmac_sha256( pass, 
                        strlen(passphrase)+sizeof(i), 
                        salt_r, 
                        salt_r_len, 
                        (BASE_ITERATION_COUNT<<iter_exponent)/ROUND_COUNT, 
                        out, 
                        r_len);
    // print_hex("round: ", out, r_len);

	memzero(salt_r, salt_r_len); free(salt_r);
    memzero(pass, sizeof(pass));
}

void _get_salt(uint16_t id, _out uint8_t* salt)
{
    memcpy(salt, CUSTOMIZATION_STRING, strlen(CUSTOMIZATION_STRING));
    int bid = be16toh(id);
    memcpy(salt+strlen(CUSTOMIZATION_STRING), &bid, sizeof(id));
}


uint16_t _generate_random_id()
{
    uint16_t r ;
    random_bytes(2, &r);
    return (uint16_t)(be16toh(r) & ((1 << ID_LENGTH_BITS) - 1));
}

void _encrypt(uint8_t* master_secret, uint16_t ms_len,
              uint8_t* passphrase,    uint16_t pp_len,
              uint8_t iter_exponent, 
              uint16_t id,  _out uint8_t* cipher)
{   
    print_hex("ms: ", master_secret, ms_len);
    print_hex("pp: ", passphrase, pp_len);
    const uint8_t salt_len = strlen(CUSTOMIZATION_STRING)+sizeof(id);
    uint8_t salt[salt_len];
    _get_salt(id, &salt);

    uint8_t half_ms_len = ms_len/2;
    uint8_t* l = malloc(half_ms_len); memzero(l, half_ms_len);
    uint8_t* r = malloc(half_ms_len); memzero(r, half_ms_len);
    uint8_t* tmp = malloc(half_ms_len); memzero(tmp, half_ms_len);
    memcpy(l, master_secret, half_ms_len);
    memcpy(r, master_secret+half_ms_len, half_ms_len);

    for(uint8_t i=0; i < ROUND_COUNT; i++) {
        _round_function(i, passphrase, iter_exponent, &salt, salt_len, r, half_ms_len, tmp);
        _xor(l, tmp, half_ms_len, tmp);
        memcpy(l, r, half_ms_len);
        memcpy(r, tmp, half_ms_len);
    }
    memcpy(cipher, r, half_ms_len);
    memcpy(cipher+half_ms_len, l, half_ms_len);

    memzero(tmp, half_ms_len);free(tmp);
    memzero(r, half_ms_len); free(r);
    memzero(l, half_ms_len); free(l);
}

void _int_to_indices(uint8_t* data, uint16_t word_len, uint8_t bits, _out uint16_t* out)
{
    uint32_t mask = (1 << bits) - 1;
    int8_t last_left = 0;
    uint8_t idx = 0;
    for(uint16_t i=0; i<word_len; i+=3) {
        uint32_t value=0;
        memcpy(&value, data+i, sizeof(value));
        value = be32toh(value);
        // dlog("value: %08x", value);
        uint8_t comp_bits = (sizeof(uint8_t)*8 - last_left) % 8;
        
        for(uint8_t j=1; j<4; j++){
            int8_t shift = sizeof(value)*8- j*bits - comp_bits;
            if(shift < 0) break;
            last_left = shift;
            out[idx++] = (value >> shift) & mask ;
        }
        if(last_left == 0) i++;
    }
}

void _int_from_indices(uint16_t* indicies, uint8_t indicies_len, 
                       _out uint8_t* out, uint8_t out_len)
{
    uint8_t idx_of_indicies = 0;
    uint8_t left_bits = 0;
    dlog("share value: ");
    for(uint8_t i=0; i<out_len; i++){
        uint8_t move_bits = 8 - left_bits;
        uint8_t value = 0;
        if(move_bits != 0)
            value = (indicies[idx_of_indicies-1] << move_bits%8) & 0xFF;

        value += (indicies[idx_of_indicies] >> ((RADIX_BITS - move_bits)%8)) & 0xFF;
        out[i] = value;
        left_bits = ((idx_of_indicies+1)*RADIX_BITS) % 8;
        if(move_bits == 0) idx_of_indicies++;
        printf("%d ", out[i]);
    }
    dlog("");
}

void menmonic_to_indicies(mnemonic_string* mnemonic_str, uint8_t mnemonic_len, _out uint16_t* indices)
{
    for(uint8_t i=0; i<mnemonic_len; i++) {
        for(uint16_t j=0; i<1024; j++) {
            if(strcmp(mnemonic_str[i].mnemonic, wordlist[j]) == 0) {
                indices[i] = j; break;
            }
        }
        printf("%d ", i);
    }
    dlog("");
}

#define MASK_ID_LOW 0x001F
#define MASK_GROPU_COUNT_LOW 0x03
int _encode_mnemonic(uint16_t id, uint8_t iter_exp, uint8_t group_index,
                      uint8_t group_threshold, uint8_t group_count,
                      uint8_t member_index, uint8_t member_threshold,
                      uint8_t* ss, uint16_t ps_len, _out mnemonic_string* mnemonic_str)
{
    uint8_t prefix_len = 5;
    dlog("id:0x%x, mem idx: %d, mem threshold: %d", id, member_index, member_threshold);
    
    // Get word indices
    uint8_t ps_word_count = BITS_TO_WORDS(ps_len*8);
    uint16_t total_words = 4+ps_word_count+CHECKSUM_LENGTH_WORDS;
    uint16_t* indices = malloc(total_words*sizeof(uint16_t));
    memzero(indices, total_words*sizeof(uint16_t));
    indices[0] = id >> (ID_LENGTH_BITS - RADIX_BITS);
    indices[1] = ((id & MASK_ID_LOW) << 5) + iter_exp;
    indices[2] = group_index; indices[2] <<=6;
    indices[2] = ((group_threshold-1)<<2) + (group_count-1)>>2;
    indices[3] = ((group_count-1) & MASK_GROPU_COUNT_LOW); indices[3] <<= 8;
    indices[3] = (member_index<<4) + (member_threshold-1) ;

    // padding share:
    uint8_t padding_len = ps_word_count*RADIX_BITS - ps_len*sizeof(uint8_t);
    uint8_t* ps = malloc(ps_len+1); memzero(ps, ps_len+1);
    ps[0] = ss[0]>>padding_len;
    for(int i=1; i<ps_len+1; i++){
        ps[i] = (ss[i-1]<<(8-padding_len)) + (ss[i]>>padding_len);
    }
    _int_to_indices(ps, ps_len, RADIX_BITS, &indices[4]);

    uint32_t checksum = _rs1024_create_checksum(indices,ps_word_count+4, &indices[4+ps_word_count]);
    dlog("checksum:0x%x", checksum);

    for(uint8_t i=0; i<total_words; i++) {
        printf("%d ", indices[i]);
    } dlog("");
    for(int i=0; i<total_words; i++) {
        printf("%s ", wordlist[indices[i]]);
        strcpy(mnemonic_str[i].mnemonic, wordlist[indices[i]]);
    }
    dlog("");

    memzero(ps, ps_len+1); free(ps); 
    memzero(indices, total_words); free(indices); 
}

int _decode_menmonic(mnemonic_string* mnemonic_str, uint8_t mnemonic_len, _out share_format* share)
{
    uint16_t* mnemonic_data = malloc(mnemonic_len);
    menmonic_to_indicies(mnemonic_str, mnemonic_len, mnemonic_data);

    uint8_t padding_len = (RADIX_BITS * (mnemonic_len - METADATA_LENGTH_WORDS))%16;
    if (padding_len > 8) {
        dlog("invalid padding len, %d", padding_len);
        return -1;
    }

    if(!rs1024_verify_checksum(mnemonic_data, mnemonic_len)){
        dlog("invalid checksum.");
        return -1;
    }

    (*share).id = mnemonic_data[0] & 0x7FFF;
    (*share).exp = mnemonic_data[1] & 0x3E0;
    (*share).group_idx = mnemonic_data[1] & 0x0F;
    (*share).group_threshod = mnemonic_data[2] & 0xF0;
    (*share).group_count = mnemonic_data[2] & 0x0F;
    (*share).member_idx = mnemonic_data[3] & 0xF0;
    (*share).member_threshod = mnemonic_data[3] & 0x0F;

    
    _int_from_indices(&mnemonic_data[4], mnemonic_len, (*share).share_value, (*share).share_value_len);

    return E_OK;
}

int _decode_mnemonics(mnemonic_string** mnemonic_str, uint8_t mnemonics_count, 
                      uint8_t mnemonic_len, _out all_shares* shares)
{
    for(uint8_t i=0; i<mnemonics_count; i++) {
        share_format a_share;
        _decode_menmonic(mnemonic_str[i], mnemonic_len, &a_share);

        uint8_t member_num = 0;
        uint8_t group_num = (*shares).group_num;
        for(uint8_t j=0; j<(*shares).group_num; j++){
            if((*shares).group_shares[j].group_idx == a_share.group_idx){
                member_num = (*shares).group_shares[j].member_num;
            }
        }
        if(member_num == 0){
            group_num ++;
        }

        (*shares).id = a_share.id;
        (*shares).exp = a_share.exp;
        (*shares).group_threshod = a_share.group_threshod;

        (*shares).group_shares[group_num].group_idx = a_share.group_idx;
        (*shares).group_shares[group_num].threshold = a_share.member_threshod;
        memcpy((*shares).group_shares[group_num].share_value, a_share.share_value, a_share.share_value_len);
        (*shares).group_shares[group_num].share_value_len = a_share.share_value_len;
        (*shares).group_shares[group_num].member_num++;


        memzero(a_share);
    }

    return E_OK;
}

// SSS

void _create_digest(uint8_t* random_data, uint16_t random_data_len, 
                    uint8_t* shared_secret, uint16_t shared_secret_len,
                    _out uint8_t* out)
{
    uint8_t mac[32];
    hmac_sha256(random_data, random_data_len, shared_secret, shared_secret_len, mac);
    memcpy(out, mac, DIGEST_LENGTH_BYTES);
}


static uint16_t EXP_TABLE[255];
static uint16_t LOG_TABLE[256];
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

void _interpolate(share_with_x* shares, uint16_t shares_len, 
                  uint16_t a_share_len, uint8_t x,
                  _out uint8_t* out)
{
    uint8_t* x_coord = malloc(shares_len);
    for(uint16_t i=0; i<shares_len; i++) {
        x_coord[i] = shares[i].x;
    }

    // TODO: check the meaning
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
        uint16_t log_basis_eval = (log_prod - LOG_TABLE[shares[i].x ^ x] - sum)%255;
        // dlog("log_basis_eval %d", log_basis_eval);

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

    // free(share_value_lengths);
    memzero(x_coord, shares_len); free(x_coord);
}

int _split_shares( uint8_t threshold, uint8_t share_count, 
                    uint8_t* secret, uint16_t secret_len,
                    _out share_with_x* shares)
{
    if(threshold < 1) {
        dlog("threshold value should be positive, %d", threshold);
        return E_INVALID_THRESHOLD_VALUE;
    }
    if(threshold > share_count) {
        dlog("invalid threshold value (%d), share count (%d)", threshold, share_count);
        return E_INVALID_THRESHOLD;
    }
    if(share_count > MAX_SHARE_COUNT){
        dlog("invalid share count, %d", share_count);
        return E_INVALID_SHARE_COUNT;
    }


    if(share_count == 1) {
        memcpy(shares[0].share, secret, secret_len); 
        shares[0].x=0;
        // print_hex("secret: ", shares[0].share, secret_len);
        return E_OK;
    }

    uint32_t digest=0;
    uint16_t random_part_len = secret_len-DIGEST_LENGTH_BYTES;
    uint8_t* random_part = malloc(random_part_len);
    memzero(random_part, random_part_len);
    random_bytes(random_part_len, random_part);
    _create_digest(random_part, random_part_len, secret, secret_len, &digest);
    // dlog("digest: 0x%x", be32toh(digest));

    share_with_x* base_shares = malloc(threshold*sizeof(share_with_x));
    uint8_t random_share_count = threshold - 2;
    for(uint8_t i=0; i<random_share_count; i++) {
        random_bytes(secret_len, base_shares[i].share);
        base_shares[i].x = i;

        memcpy(shares[i].share, base_shares[i].share, secret_len);
        shares[i].x = base_shares[i].x;
        // print_hex("random bytes: 0x", shares[i].share, secret_len);
    }
    memcpy(base_shares[threshold-2].share, &digest, DIGEST_LENGTH_BYTES);
    memcpy(base_shares[threshold-2].share+DIGEST_LENGTH_BYTES, random_part, random_part_len);
    base_shares[threshold-2].x = DIGEST_INDEX;
    memcpy(base_shares[threshold-1].share, secret, secret_len);
    base_shares[threshold-1].x = SECRET_INDEX;

    for(uint8_t i=random_share_count; i<share_count; i++) {
        _interpolate(base_shares, threshold, secret_len, i, shares[i].share);
        shares[i].x = i;
        print_hex("share: ", shares[i].share, secret_len);
    }

    memzero(base_shares, threshold*sizeof(share_with_x)); free(base_shares);
    memzero(random_part, random_part_len);free(random_part);

    // print out 
    dlog("total shares:");
    for(int i=0; i<share_count; i++) {
        print_hex(" ", shares[i].share, secret_len);
    }

    return E_OK;
}

int combin_mnemonics(mnemonic_string* mnemonic_shares, uint8_t* passphrase)
{

    dlog("done!");
    return E_OK;
}

int generate_mnemonic_shares(uint8_t* master_secret, uint16_t ms_len,
                              uint8_t* passphrase, uint16_t pp_len,
                              uint8_t group_threshold,
                              member_threshold* groups, uint8_t group_len,
                              uint8_t iter_exponent, 
                              _out mnemonic_string** mnemonic_shares)
{
    if(ms_len*8<MIN_STRENGTH_BITS || ms_len*8>MAX_STRENGTH_BITS || (ms_len%2) != 0){
        dlog("incorrect master secret len, %d", ms_len);
        return E_SECRET_SIZE;
    }
    for(uint8_t i=0; i<pp_len; i++) {
        if(!(passphrase[i]<=126 || passphrase[i] >= 32)) {
            dlog("incorrect passphrase char, [%d]=0x%x", i, passphrase[i]);
            return E_PASSPHRASE_CHAR;
        }
    }
    if(group_len < group_threshold){
        dlog("incorrect group threshold (%d), group count (%d)", group_threshold, group_len);
        return E_INVALID_THRESHOLD;
    }
    if(iter_exponent > ITERATION_EXPO_MAX){
        dlog("incorrect iteration exponent, %d", iter_exponent);
        return E_INVALID_ITERATION_EXPO;
    }
    for(uint8_t i=0; i<group_len; i++) {
        if(groups[i].count < groups[i].threshold){
            dlog("incorrect member threshold (%d), member count (%d)", groups[i].threshold, groups[i].count);
            return E_INVALID_THRESHOLD;
        }
    }

    // _precompute_exp_log();
    // dlog("group count:%d", group_len);
    uint16_t id = _generate_random_id();
    dlog("id: 0x%x", id);

    uint8_t* ems = malloc(ms_len); memzero(ems, ms_len);
    _encrypt(master_secret, ms_len, passphrase, pp_len, iter_exponent, id, ems);
    print_hex("ems: ", ems, ms_len);

    // Get group shares
    share_with_x* group_shares = malloc(group_len*sizeof(share_with_x));
    int ret =_split_shares(group_threshold, group_len, ems, ms_len, group_shares);
    if(ret != E_OK) return ret;

    // Get all mnemonics
    for(uint8_t i=0; i<group_len; i++) {
        share_with_x* member_shares = malloc(groups[i].count*sizeof(share_with_x));
        ret = _split_shares(groups[i].threshold, groups[i].count, 
                      group_shares[i].share, ms_len, member_shares);
        if(ret != E_OK) { free(member_shares); return ret; }

        for(uint8_t j=0; j<groups[i].count; j++) {
            _encode_mnemonic(id, iter_exponent, i, group_threshold, group_len, j, 
                             groups[i].threshold, member_shares[j].share, ms_len , mnemonic_shares[i]);
        }
        memzero(member_shares, groups[i].count*sizeof(share_with_x)); free(member_shares);
    }
    
    memzero(group_shares, group_len*sizeof(share_with_x)); free(group_shares);
    memzero(ems, ms_len); free(ems);

    dlog("done!");
    return E_OK;
}