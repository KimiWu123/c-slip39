
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "slip39.h"
#include "util.h"

const uint8_t g = 1;
const uint8_t gt = 1;
const uint8_t mt = 3;
const uint8_t e = 0;
const uint8_t* passphrase = "";
uint8_t ms[16]={0};

char array[][20] = {
    "depart senior academic acne club numb grin numb grin numb grin numb grin numb grin numb grin episode deliver always",
    "depart senior academic agree apart scared debris ancient remind pacific unfold brother greatest revenue promise dwarf rumor presence prospect echo", 
    "depart senior academic axle airline pancake nervous friendly crisis firm party legs drug database subject hybrid alarm enforce amount loud"
};
char a1[] = {
    "depart senior academic acne club numb grin numb grin numb grin numb grin numb grin numb grin episode deliver always"
};
char a2[] = {
    "depart senior academic agree apart scared debris ancient remind pacific unfold brother greatest revenue promise dwarf rumor presence prospect echo"
};
char a3[] = {
    "depart senior academic axle airline pancake nervous friendly crisis firm party legs drug database subject hybrid alarm enforce amount loud"
};

int main( int argc, const char* argv[] )
{
	if(argc <= 1) help();

    bool bGen = false;
    bool bRes = false;
    for(int i=0; i<argc; i++){
        if(strcmp(argv[i], "gen") == 0)
            bGen = true;
        if(strcmp(argv[i], "restore") == 0)
            bRes = true;
    }
    if(bGen){
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
        // memset(ms, 0xA3, sizeof(ms));
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
            // dlog("%x -> %x / ", &mnemonics[i], mnemonics[i]);
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

            char delim[] = " ";
            char* p = strtok(mnemonic, delim);
            int j=0;
            while(p != NULL){
                strcpy(mnemonics[i][j++].mnemonic, p);
                // printf("%s ",mnemonics[i][j-1].mnemonic);
                p = strtok(NULL, delim);
            }
            word_cnt = j-1;
            
            printf("\n");
            memzero(mnemonic, buf_size);
        }while(++i < num);
        free(mnemonic);
        
        combin_mnemonics(mnemonics, i, word_cnt, "", 0);

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
    printf("help~~~\n");
    exit(0);
}