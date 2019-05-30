#include "util.h"


void random_bytes(uint16_t size, uint8_t* out)
{
    static int initialized = 0;
	if (!initialized) {
		srand();
		initialized = 1;
	}
    for(uint16_t i=0; i<size; i++){
        out[i] = rand() & 0xFF;
    }
}

uint32_t random32(void)
{
	static int initialized = 0;
	if (!initialized) {
		srand();
		initialized = 1;
	}
	return ((rand() & 0xFF) | ((rand() & 0xFF) << 8) | ((rand() & 0xFF) << 16) | ((uint32_t) (rand() & 0xFF) << 24));
}


void print_hex(uint8_t* comment, uint8_t* hex, uint16_t len)
{
    uint8_t* cp = hex;
    printf(comment);
    for (int i=0 ; i<len; ++cp, i++ )
    {
        printf("%02x", *cp);
    }
    printf("\n");
}
