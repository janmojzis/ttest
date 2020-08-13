#include <string.h>
#include "crypto_hash_shake256.h"
#include "crypto_hash.h"

#if crypto_hash_shake256_BYTES < 32
#error
#endif
void crypto_hash_32b(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char big[crypto_hash_shake256_BYTES];
  crypto_hash_shake256(big,in,inlen);
  memcpy(out,big,32);
}
