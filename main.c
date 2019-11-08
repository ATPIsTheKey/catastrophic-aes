#include <stdio.h>
#include <stdlib.h>

#include <sodium.h>
#define SODIUMINIT if (sodium_init() == -1) return 1

#include "src/catastrophic_aes.h"

int
main()
{
    SODIUMINIT;
    return EXIT_SUCCESS;
}
