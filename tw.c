/***Author: Ewan Fleischmann***/

#include <stdio.h>
#include <tchar.h>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "miner.h"

#include "tw.h"
#include "tables.h"

#define INJECT_MSG_AND_TWIST( a ) {for( i=0; i<8; i++ ) state->hs_State[7][i] ^= (a >> (7-i)*8) & 0xFF; twist_mini_round( state );}
#define INJECT_CHECKSUM_AND_TWIST( a ) {for( i=0; i<8; i++ ) state->hs_State[7][i] ^= ( a ); twist_mini_round( state ); }

HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update( hashState *state, const BitSequence *data, DataLength databitlen );
HashReturn Final(hashState *state, BitSequence *hashval);

INTERMEDIATE_RESULT fill_intermediate_state( hashState *state, const BitSequence *data, DataLength *databitlen, DataLength *processed );

HashReturn Init(hashState *state, int hashbitlen)
{
  if ((hashbitlen>512 || hashbitlen <64) || (hashbitlen % (32)))
    return BAD_HASHBITLEN; 
  else {
    /* Set every state attribut to zero */
    memset(state, 0x0 ,sizeof(hashState));
    /* init state with counter and hash-bit-length*/
    state->hs_Counter = 0xffffffffffffffffll;
    state->hs_State[0][7] = hashbitlen >> 8;
    state->hs_State[1][7] = hashbitlen;
    state->hs_HashBitLen = hashbitlen;

    return SUCCESS;
  }
}


HashReturn Update( hashState *state, const BitSequence *data, 
          DataLength databitlen )
{
	/* return values */
	INTERMEDIATE_RESULT ir = NOT_FULL;
	DataLength processed = 0;

	state->hs_ProcessedMsgLen += databitlen; 
    /* has intermediate data block length NOT divisible by 8 => FAIL */
    if( state->hs_DataBitLen & 7 )
    {
        return FAIL;
    }

	/* is there data pending for hashing */
	if( state->hs_DataBitLen )
	{
		ir = fill_intermediate_state( state, data, &databitlen, &processed );
		if( ir == NOT_FULL ) 
			return SUCCESS;
		else
		{
			twist( state, (uint64_t*)state->hs_Data );
			state->hs_DataBitLen = 0;
		}
	}
	/* now the intermediate state is guaranteed to be clean */

	/* process all remaining full blocks */
	while( databitlen >= BLOCKSIZE )
	{
		twist( state, (uint64_t*) data+processed );
		databitlen -= BLOCKSIZE;
		processed += BLOCKSIZE;
	}
	/* save the last block for further processing */
	if( databitlen > 0 )
	{
		fill_intermediate_state( state, data+processed/8, &databitlen, &processed );
	}
	return SUCCESS;
}


HashReturn Final(hashState *state, BitSequence *hashval)
{
	uint64_t bitcntinbyte;
	uint64_t bytenum;
	int i, x, y, output_cnt;
	unsigned char ff_save[NUMROWSCOLUMNS][NUMROWSCOLUMNS];

	assert( state->hs_DataBitLen >= 0 );
	assert( state->hs_DataBitLen < BLOCKSIZE );


	// 1-0 padding 
	bitcntinbyte = state->hs_DataBitLen & 7; // modulo 8
	bytenum = state->hs_DataBitLen >> 3;     // div 8

	state->hs_Data[bytenum] &= 0xff << (8-bitcntinbyte);
	state->hs_Data[bytenum] |= 1 << (7-bitcntinbyte);

	memset( state->hs_Data+bytenum+1, 0, (STATESIZE) - bytenum - 1 );

	/* hash the padded block */
	twist( state, (uint64_t*) state->hs_Data );

	for( i=0; i<8; i++ ) state->hs_State[7][i] ^= (state->hs_ProcessedMsgLen >> (7-i)*8) & 0xFF;
	twist_mini_round( state );

	if( state->hs_HashBitLen > 256 )
	{
		/* save feed forward state */
		unsigned char ff_save[NUMROWSCOLUMNS][NUMROWSCOLUMNS];
		memcpy( ff_save, state->hs_State, sizeof state->hs_State );

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][0] )

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][1] )

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][2] )

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
		/* save feed forward state */
		memcpy( ff_save, state->hs_State, sizeof state->hs_State );

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][3] )

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][4] )

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][5] )

		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
		memcpy( ff_save, state->hs_State, sizeof state->hs_State );

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][6] )

		/* inject checksum and twist_mini_round */
		INJECT_CHECKSUM_AND_TWIST( state->hs_Checksum[i][7] )
		
		/* blank round */
		twist_mini_round( state );

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
	}
	else
	{
		twist_mini_round( state );
	}

	/* output rounds */
	assert( (state->hs_HashBitLen % 32) == 0 );

	output_cnt = 0;
	while( (output_cnt+1) * 64 <=  state->hs_HashBitLen )
	{
		unsigned char ff_save[NUMROWSCOLUMNS][NUMROWSCOLUMNS];

		/* save the feed forward state */
		memcpy( ff_save, state->hs_State, sizeof state->hs_State );
		twist_mini_round( state );
		/* FF */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
		twist_mini_round( state );

		for( i=0; i<8; i++ )
		{
			hashval[i+output_cnt*8] = state->hs_State[i][0]^ff_save[i][0];
		}
		output_cnt++;
	}
	if( (output_cnt) * 64 !=  state->hs_HashBitLen )
	{
		/* save the feed forward state */
		memcpy( ff_save, state->hs_State, sizeof state->hs_State );
		twist_mini_round( state );

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
		twist_mini_round( state );
		for( i=0; i<4; i++ )
		{
			hashval[i+output_cnt*8] = state->hs_State[i][0]^ff_save[i][0];
		}
	}
	return FAIL;
}

HashReturn Hasht1(int hashbitlen, const BitSequence *data,
		DataLength databitlen, BitSequence *hashval)
{
  hashState state;
  HashReturn i;

  if((i=Init(&state,hashbitlen))) return i;
  if((i=Update(&state,data,databitlen))) return i;
  Final(&state,hashval);
 
  return SUCCESS;
}


/* fill state withd data if a 512-bit block cannot be fully hashed */
INTERMEDIATE_RESULT fill_intermediate_state( hashState *state, const BitSequence *data, DataLength *databitlen, DataLength *processed )
{
    /* called if:   (1) intermediate state is not empty
                    (2) data to be hashed is too small i.e. no complete mini-round */
	DataLength total_bytes_to_copy = (*databitlen >> 3) + ( (*databitlen & 7) ? 1 : 0 );
	DataLength total_bits_free = BLOCKSIZE - state->hs_DataBitLen;
	DataLength total_bytes_free = total_bits_free >> 3;
	DataLength bytes_copied = MIN( total_bytes_free, total_bytes_to_copy );
	DataLength bits_copied = MIN( total_bytes_free*8, *databitlen );
	assert( (state->hs_DataBitLen & 7) == 0 );
	assert( (total_bits_free & 7) == 0 );

	memcpy( state->hs_Data + (state->hs_DataBitLen >> 3), data, (size_t) bytes_copied );

	state->hs_DataBitLen += bits_copied;

	*processed += bits_copied;
	*databitlen -= bits_copied; 

	if( state->hs_DataBitLen == BLOCKSIZE )
		return FULL;
	else
		return NOT_FULL;
}


void twist_mini_round( hashState *state )
{
	int carry = 0, oldcarry = 0, i, x, y, row, col;
	unsigned char tmp[8];
	unsigned char buf[8][8];

	/* COUNTER INPUT */
	for( i=0; i<8; i++ ) 
	{
		state->hs_State[7-i][1] = state->hs_State[7-i][1] ^ ((state->hs_Counter >> (8*i)) & 0xff); 
	}

	/* dec counter by one */
	state->hs_Counter--;

	/* SBOX */
	for( x=0; x<8; x++ )
	{
		for( y=0; y<8; y++ )
		{
			state->hs_State[y][x] = sbox[state->hs_State[y][x]];
		}
	}

	/* SHIFT ROWS */
	for( row = 1; row < 8; row++ )
	{
		for( i=0; i<8; i++ ) tmp[i] = state->hs_State[row][i];
		for( i=0; i<8; i++ ) state->hs_State[row][i] = tmp[(i+row+8)%8];
	}
	
	for( x=0; x<8; x++ ) for( y=0; y<8; y++ ) buf[y][x] = state->hs_State[y][x];

	/* MIX_COLUMS */
	for( col=0; col < 8; col++ )
	{
		// multiply with mds matrix
		for( row=0; row<8; row++ )
		{
			state->hs_State[row][col] = 
				(unsigned char)
				(
			MULT( mds[row][0], buf[0][col] ) ^
			MULT( mds[row][1], buf[1][col] ) ^
			MULT( mds[row][2], buf[2][col] ) ^
			MULT( mds[row][3], buf[3][col] ) ^
			MULT( mds[row][4], buf[4][col] ) ^
			MULT( mds[row][5], buf[5][col] ) ^
			MULT( mds[row][6], buf[6][col] ) ^
			MULT( mds[row][7], buf[7][col] )
				);
		}	
	}
}


void checksum( hashState *state, int col )
{
	int i; 
	int carry = 0, oldcarry = 0;
	
	for( i=0; i<8; i++ ) 
	{
		carry = (int) state->hs_Checksum[7-i][(col+1)%8] + (int) state->hs_State[7-i][0] + carry;
		if( carry > 255 )
		  {carry = 1;}
		else {carry = 0;}
		state->hs_Checksum[7-i][col] = state->hs_Checksum[7-i][col] ^ (state->hs_Checksum[7-i][(col+1)%8] + state->hs_State[7-i][0] + oldcarry);
		oldcarry = carry;
	}
}


void twist( hashState *state, uint64_t *msg )
{
	unsigned char ff_save[NUMROWSCOLUMNS][NUMROWSCOLUMNS];
	int i, x, y;

	/* hasbitlen > 256, e.g 384/512 bit */
	if( state->hs_HashBitLen > 256 )
	{
		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );
		/* checksum */
		checksum( state, 0 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[0] )

		/* checksum */
		checksum( state, 1 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[1] )

		/* checksum */
		checksum( state, 2 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[2] )

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}

		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );

		/* update checksum */
		checksum( state, 3 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[3] )

		//blank round;
		twist_mini_round( state );

		/* checksum */
		checksum( state, 4 );

		INJECT_MSG_AND_TWIST( msg[4] )

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}

		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );

		/* checksum */
		checksum( state, 5 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[5] )

		/* checksum */
		checksum( state, 6 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[6] )

		/* checksum */
		checksum( state, 7 );

		/* inject message and twist_mini_round */
		INJECT_MSG_AND_TWIST( msg[7] )

		// blank round
		twist_mini_round( state );

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}

	}
	else
	{   /* <= 256 bit */

		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );

		/* inject 1. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[0] )

		/* inject 2. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[1] )

		/* inject 3. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[2] )

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
		
		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );

		/* inject 3. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[3] )

		/* inject 4. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[4] )

		/* inject 5. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[5] )

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}

		/* save state for feedforward*/
		memcpy( ff_save, state->hs_State, sizeof(state->hs_State) );

		/* inject 6. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[6] )

		/* inject 7. 64-bit part of the message  */
		INJECT_MSG_AND_TWIST( msg[7] )

		/* blank round */
		twist_mini_round( state );

		/* feed forward */
		for( y=0; y<8; y++ ){for( x=0; x<8; x++ ){
			state->hs_State[y][x] ^= ff_save[y][x];}}
	}

}


int scanhash_twister(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t data[20], hash[20];
	unsigned char hash1[SHA256_DIGEST_LENGTH], hashval[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH * 2 + 1];
	unsigned char *hashc = (unsigned char *)hash;
	unsigned char *datac = (unsigned char *)data;
	unsigned char *pdatac = (unsigned char *)pdata;
	uint32_t n = pdata[19] - 1;
	int i, z;
	for (z = 0; z < 20; z++) {
		datac[(z*4)] = pdatac[(z*4)+3];
		datac[(z*4)+1] = pdatac[(z*4)+2];
		datac[(z*4)+2] = pdatac[(z*4)+1];
		datac[(z*4)+3] = pdatac[(z*4)];
	}
	do {
		data[19] = ++n;
		SHA256(datac, 80, hash1);
		int j, offset = 0;
		for (j = 0; j < SHA256_DIGEST_LENGTH; j++) {
			offset += sprintf(hash2+offset, "%02x", hash1[SHA256_DIGEST_LENGTH-j-1]);
		}
		hash2[SHA256_DIGEST_LENGTH * 2] = '\0';
		Hasht1(256, hash2, 256, hashval);
		SHA256(hashval, SHA256_DIGEST_LENGTH, hashc);
		if ((hash[7] & 0xffff0000) == 0) {
			if (fulltest(hash, ptarget)) {
				*hashes_done = n - pdata[19] + 1;
				pdatac[76] = datac[79];
				pdatac[77] = datac[78];
				pdatac[78] = datac[77];
				pdatac[79] = datac[76];
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}
