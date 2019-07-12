
#include <endian.h>
#include <stdbool.h>
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

bool rs1024_verify_checksum(uint16_t* data, uint8_t data_len)
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

    bool ret = rs1024_polymod(values, values_len) == 1;

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
              uint16_t id,  _out uint8_t* ems)
{   
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
    memcpy(ems, r, half_ms_len);
    memcpy(ems+half_ms_len, l, half_ms_len);

    memzero(tmp, half_ms_len);free(tmp);
    memzero(r, half_ms_len); free(r);
    memzero(l, half_ms_len); free(l);
}

void _decrypt(uint8_t* en_master_secret, uint16_t en_ms_len,
              uint8_t* passphrase,    uint16_t pp_len,
              uint8_t iter_exponent, 
              uint16_t id,  _out uint8_t* master_secret)
{
    const uint8_t salt_len = strlen(CUSTOMIZATION_STRING)+sizeof(id);
    uint8_t salt[salt_len];
    _get_salt(id, &salt);

    uint8_t half_ms_len = en_ms_len/2;
    uint8_t* l = malloc(half_ms_len); memzero(l, half_ms_len);
    uint8_t* r = malloc(half_ms_len); memzero(r, half_ms_len);
    uint8_t* tmp = malloc(half_ms_len); memzero(tmp, half_ms_len);
    memcpy(l, en_master_secret, half_ms_len);
    memcpy(r, en_master_secret+half_ms_len, half_ms_len);

    for(int8_t i=ROUND_COUNT-1; i>=0; i--) {
        _round_function(i, passphrase, iter_exponent, &salt, salt_len, r, half_ms_len, tmp);
        _xor(l, tmp, half_ms_len, tmp);
        memcpy(l, r, half_ms_len);
        memcpy(r, tmp, half_ms_len);
    }
    memcpy(master_secret, r, half_ms_len);
    memcpy(master_secret+half_ms_len, l, half_ms_len);

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

int _int_from_indices(uint16_t* indicies, uint8_t indicies_len, uint8_t padding_len, 
                       _out uint8_t* out, uint8_t out_len)
{
    uint8_t idx_of_indicies = 0;
    uint8_t left_bits = RADIX_BITS-padding_len;
    uint8_t padding_value = indicies[0] >> left_bits;
    if(padding_value != 0) {
        dlog("invalid padding value...");
        return E_INVALID_PADDING;
    }

    for(uint8_t i=0; i<out_len; i++){
        uint8_t move_bits = 8 - left_bits;
        // dlog("left_bits:%d, idx:%d/%d", left_bits, idx_of_indicies, indicies[idx_of_indicies]);
        if(left_bits != 0){
            out[i] = (indicies[idx_of_indicies] << move_bits) & 0xFF;
            idx_of_indicies++;
            if(left_bits%8 == 0) {
                left_bits=0; continue;
            }
        }
        out[i] += (indicies[idx_of_indicies] >> ((RADIX_BITS - move_bits))) & 0xFF;
        left_bits = RADIX_BITS - move_bits;
    }
    return E_OK;
}
 

void mnemonic_to_indicies(mnemonic_string* mnemonic_str, uint8_t mnemonic_len, _out uint16_t* indices)
{
    for(uint8_t i=0; i<mnemonic_len; i++) {
        uint16_t j=0;
        for(; i<1024; j++) {
            if(strcmp(mnemonic_str[i].mnemonic, wordlist[j]) == 0) {
                indices[i] = j; break;
            }
        }
    }
}

#define MASK_ID_LOW 0x001F
#define MASK_GROUP_COUNT_LOW 0x03
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
    indices[3] = ((group_count-1) & MASK_GROUP_COUNT_LOW); indices[3] <<= 8;
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
    // dlog("checksum:0x%x", checksum);

    for(int i=0; i<total_words; i++) {
        // printf("%s ", wordlist[indices[i]]);
        strcpy(mnemonic_str[i].mnemonic, wordlist[indices[i]]);
    }

    memzero(ps, ps_len+1); free(ps); 
    memzero(indices, total_words); free(indices); 
}

int decode_mnemonic(mnemonic_string* mnemonic_str, uint8_t mnemonic_len, _out share_format* share)
{
    uint16_t* indices = malloc(mnemonic_len*sizeof(uint16_t));
    mnemonic_to_indicies(mnemonic_str, mnemonic_len, indices);

    uint8_t padding_len = (RADIX_BITS * (mnemonic_len - METADATA_LENGTH_WORDS))%16;
    if (padding_len > 8) {
        dlog("invalid padding len, %d", padding_len);
        return E_INVALID_PADDING_LEN;
    }

    if(!rs1024_verify_checksum(indices, mnemonic_len)){
        dlog("invalid checksum.");
        return E_CHECKSUM;
    }

    (*share).id = (indices[0]<<5) + (indices[1]>>5);
    (*share).exp = (indices[1]&0x1F);
    (*share).group_idx = (indices[2]>>6) & 0x0F;
    (*share).group_threshold = ((indices[2] >> 2) & 0x0F) + 1;
    (*share).group_count = ((indices[2] & 0x03) << 2) + (indices[3]>>8) + 1;
    (*share).member_idx = ((indices[3] & 0xF0) >> 4);
    (*share).member_threshod = (indices[3] & 0x0F) + 1;
    // dlog("%d %d %d %d %d %d %d", (*share).id, (*share).exp, (*share).group_idx, 
    // (*share).group_threshold, (*share).group_count, (*share).member_idx, (*share).member_threshod);

    if((*share).group_threshold > (*share).group_count) {
        dlog("invalid group threshod (%d), group count is %d", (*share).group_threshold, (*share).group_count);
        return E_INVALID_THRESHOLD_VALUE;
    }
    if((*share).group_idx > (*share).group_count-1) {
        dlog("invalid group idx (%d), group count is %d", (*share).group_idx, (*share).group_count);
        return E_INVALID_GROUP_INDEX;
    }

    int ret = 
        _int_from_indices(&indices[4], mnemonic_len, padding_len, (*share).share_value, (*share).share_value_len);
    if(ret != E_OK) {
        dlog("int from indicies error (%d)", ret);
        return ret;
    }

    return E_OK;
}

int _decode_mnemonics(mnemonic_string** mnemonic_str, uint8_t mnemonics_count, 
                      uint8_t mnemonic_len, _out group_shares* shares, _in_out uint8_t* shares_len)
{
    int ret = E_OK;
    // dlog("\ndecode: count:%d, len:%d", mnemonics_count, mnemonic_len);
    uint8_t group_num = 0;
    for(uint8_t i=0; i<mnemonics_count; i++) {
        share_format a_share;
        a_share.share_value_len =  (mnemonic_len-METADATA_LENGTH_WORDS)*RADIX_BITS / 8 ;
        a_share.share_value = malloc(a_share.share_value_len);
        memzero(a_share.share_value, a_share.share_value_len);
        
        ret = decode_mnemonic(mnemonic_str[i], mnemonic_len, &a_share);
        if(ret != E_OK) {
            free(a_share.share_value);
            return ret;
        }
        if(*shares_len < a_share.group_count){
            *shares_len = a_share.group_count;
            free(a_share.share_value);
            return E_NOT_ENOUGH_BUFFER_SIZE;
        }
        *shares_len = a_share.group_count;

        if(i != 0 && a_share.id != (*shares).id) {
            dlog("id of shares are inconsistent...%d/%d", a_share.id, (*shares).id);
            free(a_share.share_value);
            return E_ID_INCONSISTENCE;
        }
        if(i != 0 && a_share.exp != (*shares).exp) {
            dlog("iteration numbers of shares are inconsistent...%d/%d", a_share.exp, (*shares).exp);
            free(a_share.share_value);
            return E_ITER_INCONSISTENCE;
        }
        if(i != 0 && a_share.group_count != (*shares).count) {
            dlog("group count of shares are inconsistent...%d/%d", 
                a_share.group_count, (*shares).count);
            free(a_share.share_value);
            return E_GROUP_CNT_INCONSISTENCE;
        }
        if(i != 0 && a_share.group_threshold != (*shares).threshold) {
            dlog("group threshold of shares are inconsistent...%d/%d", 
                a_share.group_threshold, (*shares).threshold);
            free(a_share.share_value);
            return E_GROUP_THR_INCONSISTENCE;
        }

        uint8_t member_num = 0;
        for(uint8_t j=0; j<a_share.group_count; j++){
            if((*shares).member_shares[j].group_idx == a_share.group_idx){
                member_num = (*shares).member_shares[j].member_num;
                for(uint8_t n=0; n<member_num; n++) {
                    if((*shares).member_shares[j].share_value != NULL &&
                        (*shares).member_shares[j].threshold != a_share.member_threshod) {
                        dlog("member threshold of shares are inconsistent...%d/%d", 
                            a_share.member_threshod, (*shares).member_shares[j].threshold);
                        free(a_share.share_value);
                        return E_MEMBER_THR_INCONSISTENCE;
                    }
                    // 
                    if( (*shares).member_shares[j].share_value != NULL &&
                        j == a_share.group_idx && 
                        (*shares).member_shares[j].share_value[n].x == a_share.member_idx) {
                        dlog("duplicated member idx %d", a_share.member_idx);
                        free(a_share.share_value);
                        return E_MEMBER_THR_INCONSISTENCE;
                    }
                }
            }
        }
        uint8_t group_idx = a_share.group_idx;
        // dlog("group[%d], mem num %d", (*shares).member_shares[group_idx].group_idx, member_num);
        // dlog("group[%d], member[%d]", group_idx, a_share.member_idx);
        // print_hex("share: ", a_share.share_value, a_share.share_value_len);
        
        (*shares).id = a_share.id;
        (*shares).exp = a_share.exp;
        (*shares).threshold = a_share.group_threshold;
        (*shares).count = a_share.group_count;
        (*shares).member_shares[group_idx].group_idx = group_idx;
        (*shares).member_shares[group_idx].threshold = a_share.member_threshod;
        
        if((*shares).member_shares[group_idx].share_value == NULL){
            (*shares).member_shares[group_idx].share_value = 
                malloc((*shares).member_shares[group_idx].threshold*sizeof(share_with_x));
        }
        share_with_x* share_x = &(*shares).member_shares[group_idx].share_value[member_num];
        memcpy((*share_x).share, a_share.share_value, a_share.share_value_len);
        (*share_x).x = a_share.member_idx;
        (*shares).member_shares[group_idx].share_value_len++;
        (*shares).member_shares[group_idx].member_num++;
        if(member_num == 0){
            group_num++;
        }

        free(a_share.share_value);
    }
    (*shares).group_num = group_num;
    if(group_num < (*shares).threshold){
        dlog("Insufficient number of mnemonic groups, %d. %d is required", group_num, (*shares).threshold);
        return E_INSUFFICIENT_MNEMONICS;
    }
    if(group_num != (*shares).threshold) {
        dlog("Wrong number of mnemonic groups (%d). Threshold:%d", (*shares).group_num, (*shares).threshold);
        return E_INCORRECT_MNEMONIC_NUM;
    }
    return ret;
}

int _split_shares( uint8_t threshold, uint8_t share_count, 
                    uint8_t* secret, uint16_t secret_len,
                    _out share_with_x* shares, uint8_t shares_len)
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

    if(threshold == 1) {
        for(uint8_t i=0; i<shares_len; i++) {
            memcpy(shares[i].share, secret, secret_len); 
            shares[i].x=i;
        }
        return E_OK;
    }

    if(share_count == 1) {
        memcpy(shares[0].share, secret, secret_len); 
        shares[0].x=0;
        return E_OK;
    }

    uint32_t digest=0;
    uint16_t random_part_len = secret_len-DIGEST_LENGTH_BYTES;
    uint8_t* random_part = malloc(random_part_len);
    memzero(random_part, random_part_len);
    random_bytes(random_part_len, random_part);
    create_digest(random_part, random_part_len, secret, secret_len, &digest);

    share_with_x* base_shares = malloc(threshold*sizeof(share_with_x));
    uint8_t random_share_count = threshold - 2;
    for(uint8_t i=0; i<random_share_count; i++) {
        random_bytes(secret_len, base_shares[i].share);
        base_shares[i].x = i;

        memcpy(shares[i].share, base_shares[i].share, secret_len);
        shares[i].x = base_shares[i].x;
    }
    memcpy(base_shares[threshold-2].share, &digest, DIGEST_LENGTH_BYTES);
    memcpy(base_shares[threshold-2].share+DIGEST_LENGTH_BYTES, random_part, random_part_len);
    base_shares[threshold-2].x = DIGEST_INDEX;
    memcpy(base_shares[threshold-1].share, secret, secret_len);
    base_shares[threshold-1].x = SECRET_INDEX;

    for(uint8_t i=random_share_count; i<share_count; i++) {
        interpolate(base_shares, threshold, secret_len, i, shares[i].share);
        shares[i].x = i;
        // print_hex("share: ", shares[i].share, secret_len);
    }

    memzero(base_shares, threshold*sizeof(share_with_x)); free(base_shares);
    memzero(random_part, random_part_len);free(random_part);

    return E_OK;
}

int _recover_secret(uint8_t threshold, share_with_x* shares_x, uint8_t shares_len, 
                    uint16_t a_share_len, _out uint8_t* secret)
{
    if(threshold == 1)  {
        memcpy(secret, shares_x[0].share, a_share_len);
        return E_OK;
    }


    uint8_t* shared_secret = malloc(a_share_len);
    memzero(shared_secret, a_share_len);
    uint8_t* digest_share = malloc(a_share_len);
    memzero(digest_share, a_share_len);
    interpolate(shares_x, shares_len, a_share_len, SECRET_INDEX, shared_secret);
    // print_hex("recovered secret: ", shared_secret, a_share_len);
    interpolate(shares_x, shares_len, a_share_len, DIGEST_INDEX, digest_share);
    // print_hex("recovered digest share: ", digest_share, a_share_len);

    uint32_t digest=0;
    uint8_t* random_part = malloc(a_share_len - DIGEST_LENGTH_BYTES);
    memcpy(&digest, digest_share, DIGEST_LENGTH_BYTES);
    for(uint8_t i=DIGEST_LENGTH_BYTES; i<a_share_len; i++){
        random_part[i-DIGEST_LENGTH_BYTES] = digest_share[i];
    }

    uint32_t digest_v=0;
    create_digest(random_part, a_share_len - DIGEST_LENGTH_BYTES, shared_secret, a_share_len, &digest_v);
    if(digest != digest_v) {
        dlog("Invalid digest, %x vs %x", digest, digest_v);
        free(digest_share); free(shared_secret);
        return E_DIGEST;
    }
    
    memcpy(secret, shared_secret, a_share_len);
    free(digest_share); free(shared_secret);
    return E_OK;
}

//
int combin_mnemonics(mnemonic_string** mnemonic_shares, uint8_t mnemonic_count, 
                     uint8_t mnemonic_len, uint8_t* passphrase, uint8_t pp_len, 
                     _out uint8_t* ms)
{
    if(mnemonic_shares == NULL) {
        dlog("The list of mnemonic is empty.");
        return E_MNEMONIC_EMPTY;
    }
    if(mnemonic_len < MNEMONIC_WORDS_MIN || mnemonic_len > MNEMONIC_WORDS_MAX) {
        dlog("Mnemonic length is not legal. (len:%d)", mnemonic_len);
        return E_INVALID_MNEMONIC_LEN;
    }

    int ret = E_OK;
    uint8_t share_value_len = (mnemonic_len-METADATA_LENGTH_WORDS)*RADIX_BITS / 8 ;
    group_shares shares; memzero(&shares, sizeof(shares));

    uint8_t share_len = 0;
    ret = _decode_mnemonics(mnemonic_shares, mnemonic_count, mnemonic_len, NULL, &share_len);
    if(ret == E_NOT_ENOUGH_BUFFER_SIZE){            
        shares.member_shares = malloc(share_len*sizeof(member_share));
        memzero(shares.member_shares, share_len*sizeof(member_share));
        ret = _decode_mnemonics(mnemonic_shares, mnemonic_count, mnemonic_len, &shares, &share_len);
    }
    if(ret != E_OK) {
        dlog("decode mnemonics failed (%d)", ret);
        return ret;
    }
    if(shares.group_num < shares.threshold){
        dlog("Group number is less than threshold, %d/%d", shares.group_num, shares.threshold);
        return E_NOT_ENOUGH_GROUPS;
    }
    

    share_with_x* group_shares = malloc(shares.group_num*sizeof(share_with_x));
    memzero(group_shares, shares.group_num*sizeof(share_with_x));
    uint8_t idx=0;
    for(uint8_t i=0; i<share_len; i++) {
        if(shares.member_shares[i].member_num < shares.member_shares[i].threshold) {
            dlog("Member number is less than threshold, %d/%d", 
                shares.member_shares[i].member_num, shares.member_shares[i].threshold);
            return E_NOT_ENOUGH_MEMBERS;
        }
        if(shares.member_shares[i].member_num == 0) continue;
        member_share a_group = shares.member_shares[i];
        ret = _recover_secret(a_group.threshold, a_group.share_value, a_group.share_value_len, 
                        share_value_len, group_shares[idx].share);
        if(ret != E_OK) {
            dlog("recover secret failed (%d)", ret);
            return ret;
        }
        group_shares[idx++].x = shares.member_shares[i].group_idx;
    }

    uint8_t* ems = malloc(share_value_len);
    memzero(ems, share_value_len);
    ret = _recover_secret(shares.threshold, group_shares, shares.group_num, share_value_len, ems);
    if(ret != E_OK) {
        dlog("recover secret failed (%d)", ret);
        return ret;
    }

    _decrypt(ems, share_value_len, passphrase, pp_len, shares.exp, shares.id, ms);
    // print_hex("master secret: ", ms, share_value_len);

    free(ems);
    free(group_shares);
    for(uint8_t i=0; i<shares.group_num; i++) {
        free(shares.member_shares[i].share_value);
    }
    free(shares.member_shares);

    return ret;
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

    // dlog("group count:%d", group_len);
    uint16_t id = _generate_random_id();

    uint8_t* ems = malloc(ms_len); memzero(ems, ms_len);
    _encrypt(master_secret, ms_len, passphrase, pp_len, iter_exponent, id, ems);

    // Get group shares
    share_with_x* group_shares = malloc(group_len*sizeof(share_with_x));
    int ret =_split_shares(group_threshold, group_len, ems, ms_len, group_shares, group_len);
    if(ret != E_OK) return ret;

    // Get all mnemonics
    for(uint8_t i=0; i<group_len; i++) {
        share_with_x* member_shares = malloc(groups[i].count*sizeof(share_with_x));
        ret = _split_shares(groups[i].threshold, groups[i].count, 
                      group_shares[i].share, ms_len, member_shares, groups[i].count);
        if(ret != E_OK) { free(member_shares); return ret; }

        for(uint8_t j=0; j<groups[i].count; j++) {
            _encode_mnemonic(id, iter_exponent, i, group_threshold, group_len, j, 
                             groups[i].threshold, member_shares[j].share, ms_len , mnemonic_shares[i]);
        }
        memzero(member_shares, groups[i].count*sizeof(share_with_x)); free(member_shares);
    }
    
    memzero(group_shares, group_len*sizeof(share_with_x)); free(group_shares);
    memzero(ems, ms_len); free(ems);

    return E_OK;
}
