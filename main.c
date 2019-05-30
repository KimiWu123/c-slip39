
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "slip39.h"

const uint8_t g = 1;
const uint8_t gt = 1;
const uint8_t mt = 3;
const uint8_t e = 0;
const uint8_t* passphrase = "";
uint8_t ms[16]={0};


int main( int argc, const char* argv[] )
{
	if(argc <= 1) help();

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
        help();
    }

    exit(0);
}

void help()
{
    printf("help~~~\n");
    exit(0);
}