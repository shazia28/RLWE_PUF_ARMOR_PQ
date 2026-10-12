#ifndef NTT_H
#define NTT_H

#include "rlwe_core.h"

void ntt(Polynomial* a);
void inv_ntt(Polynomial* a);
void create_ntt_table(void);

#endif
