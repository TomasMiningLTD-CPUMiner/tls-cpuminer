/***2014 Tlascoin Project***/

#define DEBUG

#define MIN(a,b) ((a)>(b)?(b):(a))

#define NUMROWSCOLUMNS 512 
#define STATESIZE NUMROWSCOLUMNS * NUMROWSCOLUMNS

#define BLOCKSIZE 512

#ifdef __GNUC__
#include <stdint.h>
#else
typedef unsigned __int64 uint64_t;
#endif

#define MULT(a,b) (multab[a-1][b])

typedef unsigned char BitSequence;
typedef uint64_t DataLength;
typedef enum {SUCCESS=0, FAIL=1, BAD_HASHBITLEN=2 } HashReturn;
typedef enum {FULL = 0, NOT_FULL = 1 } INTERMEDIATE_RESULT;

typedef struct {

  unsigned char hs_State[NUMROWSCOLUMNS][NUMROWSCOLUMNS];

  unsigned char hs_Checksum[NUMROWSCOLUMNS][NUMROWSCOLUMNS];

  DataLength hs_ProcessedMsgLen;

  BitSequence hs_Data[STATESIZE];    

  uint64_t hs_DataBitLen;

  uint64_t hs_Counter;

  /* output hash bit length, in bits */
  uint64_t hs_HashBitLen;

} hashState;

HashReturn Init(hashState *state, int hashbitlen);

HashReturn Update(hashState *state, const BitSequence *data, 
		  DataLength databitlen);

HashReturn Final(hashState *state, BitSequence *hashval);

HashReturn Hasht1(int hashbitlen, const BitSequence *data,
		DataLength databitlen, BitSequence *hashval); 

INTERMEDIATE_RESULT fill_intermediate_state( hashState *state, const BitSequence *data, DataLength *databitlen, DataLength *processed );
void twist( hashState *state, uint64_t *data );
void twist_mini_round( hashState *state );
void checksum( hashState *state, int col );
