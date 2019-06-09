
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
	if(argc <= 1) return help();

    bool bGen=false;
    for(int i=0; i<argc; i++){
        if(strcmp(argv[i], "gen") == 0)
            bGen = true;
    }
    if(bGen){
        mnemonic_string mnemonics[MAX_SHARE_COUNT][MAX_SHARE_COUNT] ;
        member_threshold mthres[g];
        for(uint8_t i=0; i<g; i++) {
            mthres[i].count = 5;
            mthres[i].threshold = 3;
        }
        memset(ms, 0xA3, sizeof(ms));
        generate_mnemonic_shares(ms, sizeof(ms), passphrase, 0, gt, mthres, g, e, mnemonics);
    } else {
        mnemonic_string** mnemonics;
        mnemonics = malloc(sizeof(mnemonic_string)*MAX_SHARE_COUNT);
        for(int i=0; i<MAX_SHARE_COUNT; i++){
            mnemonics[i] = malloc(sizeof(mnemonic_string)*33);
            // dlog("%x -> %x / ", &mnemonics[i], mnemonics[i]);
        }

        // mnemonic_string mnemonics[MAX_SHARE_COUNT][MAX_SHARE_COUNT] ;
        char delim[] = " ";

        char* p = strtok(a1, delim);
        int j=0;
        while(p != NULL){
            strcpy(mnemonics[0][j++].mnemonic, p);
            printf("%s ",mnemonics[0][j-1].mnemonic);
            p = strtok(NULL, delim);
        }dlog("");
        p = strtok(a2, delim);
        j=0;
        while(p != NULL){
            strcpy(mnemonics[1][j++].mnemonic, p);
            // printf("%s ",mnemonics[1][j-1].mnemonic);
            p = strtok(NULL, delim);
        }
        p = strtok(a3, delim);
        j=0;
        while(p != NULL){
            strcpy(mnemonics[2][j++].mnemonic, p);
            // printf("%s ",mnemonics[2][j-1].mnemonic);
            p = strtok(NULL, delim);
        }
        
        // for(int i=0; i<3; i++) {
        //     printf("%s \n",array[i]);
        //     char* p = strtok(array[i], delim);
        //     int j=0;
        //     while(p != NULL){
        //         strcpy(mnemonics[i][j++].mnemonic, p);
        //         printf("%s ",p);
        //         p = strtok(NULL, delim);
        //     }

        //     printf("\n");
        // }
        
        
        combin_mnemonics(mnemonics, 3, 20, "", 0);
    }

    exit(0);
}

int help()
{
    printf("help~~~\n");
    exit(0);
    return 0;
}