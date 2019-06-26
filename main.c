
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "slip39.h"
#include "util.h"
#include "cJSON.h"

const uint8_t g = 1;
const uint8_t gt = 1;
const uint8_t mt = 3;
const uint8_t e = 0;
const uint8_t* passphrase = "";
uint8_t ms[16]={0};


uint8_t parse_mnemonic_strings(char* mnemonic_str, _out mnemonic_string* mnemonic_struct)
{
    char delim[] = " ";
    char* p = strtok(mnemonic_str, delim);
    int j=0;
    while(p != NULL){
        strcpy(mnemonic_struct[j++].mnemonic, p);
        // printf("%s ",mnemonics_st[i][j-1].mnemonic);
        p = strtok(NULL, delim);
    }
    return j;
}

int main( int argc, const char* argv[] )
{
	if(argc <= 1) help();

    bool bGen = false;
    bool bRes = false;
    bool bTest = false;
    for(int i=0; i<argc; i++){
        if(strcmp(argv[i], "gen") == 0)
            bGen = true;
        if(strcmp(argv[i], "restore") == 0)
            bRes = true;
        if(strcmp(argv[i], "test") == 0)
            bTest = true;
    }
    if(bTest){
        if(argc < 2) 
            help(); 
        test(argv[2]);
    }
    else if(bGen){
        uint8_t threshold = 3;
        uint8_t count = 5;
        if(argc > 2) {
            char* idx = strstr(argv[2], "of");
            if(idx != NULL){
                threshold = idx-1;
                count = idx+2;
            }
        }

        mnemonic_string mnemonics[MAX_SHARE_COUNT][MAX_SHARE_COUNT] ;
        member_threshold mthres[g];
        for(uint8_t i=0; i<g; i++) {
            mthres[i].count = count;
            mthres[i].threshold = threshold;
        }
        random_bytes(sizeof(ms), ms);
        generate_mnemonic_shares(ms, sizeof(ms), passphrase, 0, gt, mthres, g, e, mnemonics);
    } else if(bRes) {
        int num=0;
        printf("How many shares: ");
        scanf("%d", &num);

        mnemonic_string** mnemonics;
        mnemonics = malloc(sizeof(mnemonic_string)*num);
        for(int i=0; i<num; i++){
            mnemonics[i] = malloc(sizeof(mnemonic_string)*33);
        }

        const uint32_t buf_size = 33*(MNEMONIC_MAX_LEN+1)+1;
        char* mnemonic = malloc(buf_size);
        memzero(mnemonic, buf_size);
        uint8_t i=0;
        uint8_t word_cnt = 0;
        do {
            printf("Enter a recovery share: %d of %d \n", i, num);
            fgets(mnemonic, buf_size, stdin);
            if(strlen(mnemonic) < MNEMONIC_MAX_LEN) {i--; continue;}

            word_cnt = parse_mnemonic_strings(mnemonic, mnemonics[i])-1;
            printf("\n");
            memzero(mnemonic, buf_size);
        }while(++i < num);
        free(mnemonic);
        
        uint8_t share_value_len = (word_cnt-METADATA_LENGTH_WORDS)*RADIX_BITS / 8 ;
        uint8_t* ms = malloc(share_value_len); memzero(ms, share_value_len);
        combin_mnemonics(mnemonics, i, word_cnt, "", 0, ms);
        print_hex("secret: ", ms, share_value_len);

        for(int i=0; i<num; i++){
            free(mnemonics[i]);
        }
        free(mnemonics);
    }
    else {
        help();
    }

    exit(0);
}

void help()
{
    printf("help~~ help~~\n\n");
    printf("Command: \n");
    printf("  gen:  generate Shamir mnemonics...\n");
    printf("        nofm, eg: 3of5\n");
    printf("  recover\n");
    printf("  test: test with test vectors\n");
    printf("        <file name>, eg: vectors.json\n");
    exit(0);
}

void test(char* filename) {
    FILE* fp = fopen(filename, "r");
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* buf = malloc(size);
    memzero(buf, size);

    size_t read_Bytes = fread(buf, 1, size, fp);
    if(read_Bytes <=0 ){
        free(buf);
        fclose(fp); 
        printf("read %s failed", filename);
        exit(-1);
    }
    cJSON *json = cJSON_Parse(buf);

    int total_cases = cJSON_GetArraySize(json);
    int pass_cases = 0;
    printf("== total %d cases ==\n", total_cases);
    for(int n=0; n<cJSON_GetArraySize(json); n++) {
        cJSON* test_case = cJSON_GetArrayItem(json, n);
        if((*test_case).type == cJSON_Array) {
            bool valid = true;
            cJSON* desc = cJSON_GetArrayItem(test_case, 0);
            printf("\n%s", (*desc).valuestring);
            
            cJSON* secret = cJSON_GetArrayItem(test_case, 2);
            if(strlen((*secret).valuestring) == 0) {
                valid = false;
            }
            cJSON* mnemonics = cJSON_GetArrayItem(test_case, 1);
            int mnemonics_len = cJSON_GetArraySize(mnemonics);

            mnemonic_string** mnemonics_st = malloc(sizeof(mnemonic_string)*mnemonics_len);
            memzero(mnemonics_st, sizeof(mnemonic_string)*mnemonics_len);
            
            const uint32_t buf_size = 33*(MNEMONIC_MAX_LEN+1)+1;
            uint8_t word_cnt = 0;
            for(int i=0; i<mnemonics_len; i++){
                mnemonics_st[i] = malloc(sizeof(mnemonic_string)*33);
                cJSON* tmp = cJSON_GetArrayItem(mnemonics, i);
                word_cnt = parse_mnemonic_strings((*tmp).valuestring, mnemonics_st[i]);
            }

            uint8_t share_value_len = (word_cnt-METADATA_LENGTH_WORDS)*RADIX_BITS / 8 ;
            uint8_t* ms = malloc(share_value_len); memzero(ms, share_value_len);
            int ret = combin_mnemonics(mnemonics_st, mnemonics_len, word_cnt, "TREZOR", 6, ms);

            char* str_ms = malloc(share_value_len*2+1); memzero(str_ms, share_value_len+1);
            if(ret == E_OK) {
                for(int s=0; s<share_value_len; s++){
                    sprintf(&str_ms[s*2], "%02x", ms[s]);
                } printf("ms: %s\n", str_ms);
            }
            
            // print out the results 
            if(valid) {
                if(strcmp((*secret).valuestring, (char*)str_ms) == 0){
                    printf("PASS! \n");
                    pass_cases++;
                } else {
                    printf("FAILED\n ");
                    printf("secret should be : %s\n", (*secret).valuestring);
                }
            } else {
                if(ret != E_OK) {
                    printf("PASS! \n");
                    pass_cases++;
                }
                else
                    printf("FAILED\n");
            }

            // free resources
            if(str_ms) {
                free(str_ms); str_ms = NULL;
            }
            if(ms) {
                free(ms); ms = NULL;
            }
            for(int i=0; i<mnemonics_len; i++){
                if(mnemonics_st[i]) {
                    free(mnemonics_st[i]); mnemonics_st[i] = NULL;
                }
            }
            if(mnemonics_st) {
                free(mnemonics_st); mnemonics_st = NULL;
            }
        }
    }
    printf("\n == PASS: %d/%d cases ==\n", pass_cases, total_cases);
    if(buf) free(buf);
    fclose(fp);
}
