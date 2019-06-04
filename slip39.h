#ifndef __SLIP39_H__
#define __SLIP39_H__

#include <stdint.h>

#define _out

// """The length of the radix in bits."""
#define RADIX_BITS 10

// """The number of words in the wordlist."""
#define RADIX 2 ** RADIX_BITS

// """The length of the random identifier in bits."""
#define ID_LENGTH_BITS 15

// """The length of the iteration exponent in bits."""
#define ITERATION_EXP_LENGTH_BITS 5

// """The length of the random identifier and iteration exponent in words."""
#define ID_EXP_LENGTH_WORDS BITS_TO_WORDS(ID_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS)

// """The maximum number of shares that can be created."""
#define MAX_SHARE_COUNT 16

// """The length of the RS1024 checksum in words."""
#define CHECKSUM_LENGTH_WORDS  3

// """The length of the digest of the shared secret in bytes."""
#define DIGEST_LENGTH_BYTES 4

// """The customization string used in the RS1024 checksum and in the PBKDF2 salt."""
#define CUSTOMIZATION_STRING "shamir"

// """The length of the mnemonic in words without the share value."""
#define METADATA_LENGTH_WORDS (ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS)

// """The minimum allowed entropy of the master secret."""
#define MIN_STRENGTH_BITS 128
#define MAX_STRENGTH_BITS 256

// """The minimum allowed length of the mnemonic in words."""
#define MIN_MNEMONIC_LENGTH_WORDS (METADATA_LENGTH_WORDS + BITS_TO_WORDS(MIN_STRENGTH_BITS))

// """The minimum number of iterations to use in PBKDF2."""
#define BASE_ITERATION_COUNT 10000

#define ITERATION_EXPO_MAX  (1<<5)

// """The number of rounds to use in the Feistel cipher."""
#define ROUND_COUNT 4

//  """The index of the share containing the shared secret."""
#define SECRET_INDEX 255

// """The index of the share containing the digest of the shared secret."""
#define DIGEST_INDEX 254

#define MNEMONIC_MAX_LEN 8
#define MNEMONIC_MIN_LEN 4

#define BITS_TO_BYTES(n) ((n+7)/8)
#define BITS_TO_WORDS(n) ((n+RADIX_BITS-1)/RADIX_BITS)

typedef struct __share_with_x {
    uint8_t share[32];
    uint8_t  x;
} share_with_x;

// decode
typedef struct __group_share {
    uint8_t group_idx;
    uint8_t threshold;
    share_with_x* share_value;
    uint8_t share_value_len;
    uint8_t member_num;
} group_share;

typedef struct __all_shares {
    uint16_t id;
    uint8_t exp;
    
    uint8_t group_threshod;
    uint8_t group_count;
    group_share* group_shares;
    uint8_t group_num;
} all_shares;

typedef struct __share_format {
    uint16_t id;
    uint8_t exp;
    uint8_t group_idx;
    uint8_t group_threshod;
    uint8_t group_count;
    uint8_t member_idx;
    uint8_t member_threshod;
    uint8_t* share_value;
    uint8_t share_value_len;
} share_format;

// encode 
typedef struct __mnemonic_string {
    uint8_t mnemonic[MNEMONIC_MAX_LEN+1];
} mnemonic_string;

typedef struct __member_threshold {
    uint8_t threshold;
    uint8_t count;
} member_threshold;



int generate_mnemonic_shares(uint8_t* master_secret, uint16_t ms_len,
                              uint8_t* passphrase, uint16_t pp_len,
                              uint8_t group_threshold,
                              member_threshold* groups, uint8_t group_len,
                              uint8_t iter_exponent, 
                              _out mnemonic_string** mnemonic_shares);

int combin_mnemonics(mnemonic_string** mnemonic_shares, uint8_t mnemonic_count, 
                     uint8_t mnemonic_len, uint8_t* passphrase, uint8_t pp_len);
#define E_OK 0
#define E_SECRET_SIZE       -1
#define E_PASSPHRASE_CHAR   -2
#define E_INVALID_THRESHOLD   -3
// #define E_INVALID_MEMBER_THRESHOLD  -4
#define E_INVALID_ITERATION_EXPO    -4

#define E_INVALID_THRESHOLD_VALUE   -5
#define E_INVALID_SHARE_COUNT       -6

#endif