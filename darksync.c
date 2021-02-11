#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
// todo: remove these for "getrandom" function
#include <sys/syscall.h>
#include <linux/random.h>

#define CBC 1
#define AES256 1
#define AES_BLOCKLEN 16
#define AES_KEYLEN 32
#define AES_keyExpSize 240

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};
/*

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey); 
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey); 

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = (Nr - 1); round > 0; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, uint32_t length)
{
  uintptr_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
    //printf("Step %d - %d", i/16, i);
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length)
{
  uintptr_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  unsigned i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif // #if defined(CTR) && (CTR == 1)


#define RPORT 8686
#define SPORT 8687
#define MAXCONN 50
#define MAXMSGLEN 256
#define MAXFILESIZE 8*1000*1000 // 100 MB

//------- Identifiers
#define ACTIVE_NODES_REQ 0xF0
#define DISCONNECT 0xF1
#define STD_MSG 0xF2
#define NODE_RES 0xF3
#define HELLO 0xF4
#define BL_UPD 0xF5
#define F_MSG 0xF6

//------- Structures
// User Input
struct arguments_s{
    char* key;
    char* node_ip;
    char* nickname;
};
typedef struct arguments_s* Arguments;

// Ip linked list
struct ip_list_s{
    uint32_t ip;
    char nick[20];
    struct ip_list_s* next;
};
typedef struct ip_list_s* IP_List;

void IPL_add(uint32_t ip, IP_List* root, char* nickname);
void IPL_print(IP_List root);
void IPL_destroy(IP_List root);
char* IPL_contains(uint32_t ip, IP_List root);
int IPL_remove(uint32_t ip, IP_List* root);

// Message List
struct message_list_s{
    char message[MAXMSGLEN];
    char nick[20];
    uint32_t time;
    struct message_list_s* next;
};
typedef struct message_list_s* MSG_List;

void MSG_add(char* message, char* nick, uint32_t time, MSG_List* messages);
void MSG_destroy(MSG_List messages);
void MSG_display(MSG_List messages);

// Metadata
struct metadata_s{
    int ip_count;
    int blacklist_count;
    uint32_t my_ip;
    int reciever_s;
    int sender_s;
    char nick[20];
    IP_List ip_list;
    IP_List blacklist;
    MSG_List messages;
    unsigned int lock: 2;
    unsigned int ipassive: 1;
    unsigned int emit_black: 1;
    unsigned int keyloaded: 1;
    uint8_t key[32];
    uint8_t iv[16];
    struct AES_ctx* encrypt_context;
};
typedef struct metadata_s* Metadata;

struct message_s{
    uint8_t identifier;
    int size;
    uint8_t* message;
};
typedef struct message_s* Message;

//------- encryption
void generate_key_256();
void load_key(char* key, Metadata meta);
int send_message_encrypted(Message m, int socket, Metadata meta);

//------- blacklist
void load_blacklist(IP_List* root, Metadata meta);
void dump_blacklist(IP_List root);

//------- voids
void print_usage(); // print the usage
void create_directories(); // create the .darkchat and keys if not present
void check_args(); // validate arguments
void print_ip(uint32_t ip); // print in human readable

//------- aux
uint32_t conv_ip(char* ip); // check and convert the ip

//------- socket
int init_socket();
uint32_t getlocalip();
int send_message(Message m, int socket);

//------- threading
void* message_reciever_worker(void* arg);
void* message_sender_worker(void* arg);

//------- locks
void lock(Metadata meta);
void unlock(Metadata meta);

//------- destruction
void destructor(Arguments args, Metadata meta);

// Ip linked list
void IPL_add(uint32_t ip, IP_List* root, char* nickname){
    if(!(*root)){
        (*root) = calloc(1,sizeof(struct ip_list_s));
        (*root)->ip = ip;
        (*root)->next = NULL;
        memcpy((*root)->nick,nickname,20);
    }
    else{
        IP_List temp = *root;
        while(temp->next){
            temp = temp->next;
        }
        temp->next = calloc(1,sizeof(struct ip_list_s));
        temp->next->ip = ip;
        memcpy(temp->next->nick,nickname,20);
        temp->next->next = NULL;
    }
}

void IPL_print(IP_List root){
    if(root){
        print_ip(root->ip);
        printf(" (%s)",root->nick);
        printf("\n");
        if(root->next)
            IPL_print(root->next);
    }
}

void IPL_destroy(IP_List root){
    if(root){
        if(root->next)
            IPL_destroy(root->next);
        free(root);
    }
}

char* IPL_contains(uint32_t ip, IP_List root){
    char* ret = NULL;
    if(root){
        if(root->ip == ip){
            ret = malloc(20);
            memcpy(ret, root->nick, 20);
            return ret;
        }
        if(root->next)
            ret = IPL_contains(ip,root->next);
    }
    return ret;
}

int IPL_remove(uint32_t ip, IP_List* root){
    IP_List temp = *root;
    if(temp->ip == ip){ // its the head
        temp = (*root)->next;
        free(*root);
        (*root) = temp;
        return 1;
    }
    else{ // find it
        IP_List prev = (*root);
        IP_List current = (*root)->next;
        while(current && current->ip != ip){
            prev = current;
            current = prev->next;
        }
        // remove current
        if(current){
            IP_List temp = current->next;
            free(current);
            prev->next = temp;
            return 1;
        }
        else
            return 0;
    }
}

// Message List

void MSG_add(char* message, char* nick, uint32_t time, MSG_List* messages){
    if(!(*messages)){
        (*messages) = calloc(1,sizeof(struct message_list_s));
        memcpy((*messages)->message, message, MAXMSGLEN);
        memcpy((*messages)->nick, nick, 20);
        (*messages)->time = time;
        (*messages)->next = NULL;
    printf("[%s] %s\n", nick, message);
    }
    else{
        MSG_List temp = *messages;
        while(temp->next)
            temp = temp->next;
        temp->next = calloc(1,sizeof(struct message_list_s));
        memcpy(temp->next->message, message, MAXMSGLEN);
        memcpy(temp->next->nick, nick, 20);
        temp->next->time = time;
        temp->next->next = NULL;
    printf("[%s] %s\n", nick, message);
        
    }
}

void MSG_destroy(MSG_List messages){
    if(messages){
        if(messages->next)
            MSG_destroy(messages->next);
        free(messages);
    }
}

void MSG_display(MSG_List messages){
    if(messages){
        printf("[%s @ ",messages->nick);
        printf("]: %s",messages->message);
        if(messages->next)
            MSG_display(messages->next);
    }
}


// Aux
uint32_t conv_ip(char* ip){
    uint32_t result=0;
    char oct[16]={0};
    int o;
    int p = 0;
    int octet, byte;
    //rip apart inputed data and validate
    for(octet = 0; octet<4; octet++){
        o = octet*4;
        if(octet<3){ // first 3 octets
            while(ip[p]!='.'){
                if(p==o+4){
                    fprintf(stderr, "IP: %s is not a valid IP.\n",ip);
                    exit(EXIT_FAILURE);
                }
                oct[o]=ip[p];
                p++;
                o++;
            }
            p++;
            oct[o] ='\0';
        }
        else{ // last octet
            strncpy(oct+12,ip+p,4);
            oct[15] = '\0';
        }
    }
    // convert to uint32_t while checking fields
    for(byte=3;byte>=0;byte--){
        char b[4]={0};
        strncpy(b,oct+(byte*4),4);
        int x = strtol(b,NULL,10);
        if(x>255){
            fprintf(stderr,"IP: %s is not a valid IP.\n",ip);
            exit(EXIT_FAILURE);
        }
        result |= (uint8_t)x;
        if(byte>0)
            result <<= 8;
    }
    return result;
}

// encryption
void generate_key_256(){
    uint8_t key[32];
    syscall(SYS_getrandom,key,32,0);
    char path[50] = {0};
    snprintf(path, sizeof path, "%s/.darksync/keys/key_%ld", getenv("HOME"),time(NULL));
    FILE* key_file = fopen(path,"w");
    fwrite(key,1,32,key_file);
}

void load_key(char* key, Metadata meta){
    if(key[0]!='0'&&key[1]!='\0'){
        char path[100] = "";
        strcat(path,getenv("HOME"));
        strcat(path,"/.darksync/keys/");
        strcat(path,key);
        FILE* keyfile = fopen(path,"r");
        if(!keyfile){
            fprintf(stderr,"Key does not exist. Exiting\n");
            meta->keyloaded = 0;
            exit(EXIT_FAILURE);
        }
        fread(meta->key,1,32,keyfile);
        meta->keyloaded = 1;
    }
}

int send_message_encrypted(Message m, int socket, Metadata meta){
    int buffer_size = m->size;
    if(buffer_size<16)
        buffer_size = 16;
    else if(buffer_size%16)//apply padding
        buffer_size = (buffer_size/16)*16+(buffer_size%16)*16;
    uint8_t* buffer = calloc(buffer_size, 1);
    buffer[0] = m->identifier;
    int byte;
    if(m->size > 1)
        for(byte = 1; byte < m->size; byte++){
            buffer[byte] = (m->message)[byte-1];
        }
    AES_init_ctx_iv(meta->encrypt_context, meta->key, meta->iv);
    AES_CBC_encrypt_buffer(meta->encrypt_context,buffer,buffer_size);
    send(socket , buffer , buffer_size, 0 );
    free(buffer);
    return 0;
}

// Blacklist
void load_blacklist(IP_List* root, Metadata meta){
    char path[1024] = {0};
    strcat(path, getenv("HOME"));
    strcat(path,"/.darksync/blacklist.txt");
    FILE* blacklist = fopen(path, "r");
    if(blacklist){
        size_t n = 0;
        char* ip = NULL;
        int nread = 0;
        nread = getline(&ip,&n,blacklist);
        while(nread != -1){
            IPL_add(conv_ip(ip),root,"bad");
            meta->blacklist_count++;
            free(ip);
            ip = NULL;
            nread = getline(&ip,&n,blacklist);
        }
        fclose(blacklist);
        free(ip);
    }
}

void dump_blacklist(IP_List root){
    char path[1024] = {0};
    strcat(path, getenv("HOME"));
    strcat(path,"/.darksync/blacklist.txt");
    FILE* blacklist = fopen(path, "w+");
    IP_List temp = root;
    int i;
    while(temp){
        uint8_t octet[4]={0};
        for(i = 0 ; i < 4 ; i++)
            octet[i] = temp->ip >> (i * 8);
        fprintf(blacklist,"%d.%d.%d.%d\n",octet[0],octet[1],octet[2],octet[3]);
        temp = temp->next;
    }
    fclose(blacklist);
}

// Voids
void print_usage(){
    fprintf(stderr,"Usage: darksync [key] [node_ip] [nickname] [interface]\n \
            \tkey: AES key name, 0 to start with no key loaded (careful, if you send a message in this mode you may be blacklisted).\n \
            \tnode_ip: ip of active chat node (enter \"p\" to start in passive mode)\n \
            \tnickname: chat nickname\n \
            \tinterface: desired interface, IE: wlp4s0\n\n \
            \tNote: place key file in $HOME/.darksync/keys dir\n");
}

void create_directories(){
    struct stat st = {0};
    char path[1024] = {0};
    strcat(path, getenv("HOME"));
    strcat(path,"/.darksync");
    if (stat(path, &st) == -1)
        mkdir(path, 0700);
    strcat(path,"/keys");
    if (stat(path,&st) == -1)
        mkdir(path, 0700);
    char fp[1024] = {0};
    strcat(fp, getenv("HOME"));
    strcat(fp,"/.darksync");
	strcat(fp,"/files");
	if (stat(fp,&st) == -1)
        mkdir(fp, 0700);
}

void check_args(char* argv[]){
    // check key file
    size_t byte;
    if(strlen(argv[1])>50){
        fprintf(stderr,"Key filename to long, rename it.\n");
        exit(EXIT_FAILURE);
    }
    for(byte=0; byte<strlen(argv[1]); byte++){
        uint8_t b = argv[1][byte];
        if( b > 122 || b < 33 ){
            fprintf(stderr,"Key file name should only contain ASCII 33 - 122.\n");
            exit(EXIT_FAILURE);
        }
    }
    // check ip
    if(!(argv[2][0]=='p'&&strlen(argv[2])==1)){
        if(strlen(argv[2])>15){
            fprintf(stderr,"Invalid IP.\n");
            exit(EXIT_FAILURE);
        }
        for(byte=0; byte<strlen(argv[2]); byte++){
            uint8_t b = argv[2][byte];
            if( (b < 48 || b > 57) && b != 46 ){
                fprintf(stderr,"Invalid IP.\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    // check nickname
    if(strlen(argv[3])>19){
        fprintf(stderr,"Try using a shorter nickname.\n");
        exit(EXIT_FAILURE);
    }
    for(byte=0; byte<strlen(argv[3]); byte++){
        uint8_t b = argv[3][byte];
        if( b > 122 || b < 33 ){
            fprintf(stderr,"Nickname should only contain ASCII 33 - 122.\n");
            exit(EXIT_FAILURE);
        }
    }
}

void print_ip(uint32_t ip){
    uint8_t octet[4];
    short i;
    for(i = 0 ; i < 4 ; i++)
        octet[i] = ip >> (i * 8);
    printf("%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
}

// Socket
int init_socket(int port){
    struct sockaddr_in address;
    int sockfd;
    int opt = 1;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        fprintf(stderr,"socket failed");
        exit(EXIT_FAILURE);
    }
    // force port 8686
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
        fprintf(stderr,"setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address))<0){
        fprintf(stderr,"bind failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

uint32_t getlocalip(){
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) return 0;

    struct sockaddr_in serv;
    memset( & serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    int err = connect(sock, (const struct sockaddr * ) & serv, sizeof(serv));
    if (err == -1) return 0;

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr * ) & name, & namelen);
    if (err == -1) return 0;

    close(sock);

    return name.sin_addr.s_addr;
  }


int send_message(Message m, int socket){
    uint8_t* buffer = calloc(1024, 1);
    buffer[0] = m->identifier;int byte;
    if(m->size > 1)
        for(byte = 1; byte < m->size; byte++){
            buffer[byte] = (m->message)[byte-1];
        }
    send(socket , buffer , 1024, 0 );
    free(buffer);
    return 0;
}

// Threading
void* message_reciever_worker(void* arg){
    if(fork()>0) return;
    Metadata meta = (Metadata)arg;
                int c, b, i, ip;

    while(meta->lock!=2){
        if (listen(meta->reciever_s, MAXCONN) < 0){
            fprintf(stderr, "failed on listen\n");
            exit(EXIT_FAILURE);
        }
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        int new_socket;
        if ((new_socket = accept(meta->reciever_s, (struct sockaddr *)&address,(socklen_t*)&addrlen))<0){
            if(meta->lock!=2){
                printf("failed on accept");
                exit(EXIT_FAILURE);
            }
            else{
                break;
            }
        }
        char* nick = IPL_contains(address.sin_addr.s_addr,meta->blacklist);
        if(nick){ // blacklist check
            close(new_socket); // ciao ciao
            free(nick);
        }
        else{
            int buf_len = (MAXFILESIZE/16)*16+(MAXFILESIZE%16)*16;
            uint8_t* message = calloc(buf_len,1);
            read(new_socket , message, buf_len);
            AES_init_ctx_iv(meta->encrypt_context, meta->key, meta->iv);
            AES_CBC_decrypt_buffer(meta->encrypt_context,message,buf_len);
            if(message[0]==ACTIVE_NODES_REQ){ // node list request
                lock(meta);
                //extract nickname
                char temp_nick[20] = {0};
                for(c = 1; c <= 20; c++){
                    temp_nick[c-1] = message[c];
                }
                //add message
                char* conn = calloc(100,1);
                strcat(conn,inet_ntoa(address.sin_addr));
                strcat(conn," (");
                strcat(conn,temp_nick);
                strcat(conn,") connected.\0");
                MSG_add(conn, "~", time(NULL), &(meta->messages));
                free(conn);
                meta->ip_count = 1;
                Message ip_list_message = calloc(1,sizeof(struct message_s));
                ip_list_message->identifier = NODE_RES;
                ip_list_message->size = (meta->ip_count*4)+2+20+1+(meta->blacklist_count*4);
                ip_list_message->message = calloc((meta->ip_count*4)+2+20+1+(meta->blacklist_count*4),1);
                ip_list_message->message[0] = meta->ip_count;
                for(c = 1; c <= 20; c++){
                    ip_list_message->message[c] = meta->nick[c-1];
                }
                int offset = 1+20;
                IP_List temp = meta->ip_list;
                for(ip = 0; ip < meta->ip_count; ip++){// for each ip
                    uint32_t ipad = temp->ip; // copy the ip
                    for(b = 3; b >= 0; b--){ // bytes in decending order
                        ip_list_message->message[offset+b] |= ipad&0xFF; // set the byte
                        ipad >>= 8; // shift to next
                    }
                    offset+=4; // jump forward 4 bytes in the message
                    temp = temp->next; // get the next ip
                }
                // add current blacklist
                ip_list_message->message[offset] = meta->blacklist_count;
                offset++;
                temp = meta->blacklist;
                for(ip = 0; ip < meta->blacklist_count; ip++){// for each ip
                    uint32_t ipad = temp->ip; // copy the ip
                    for(b = 3; b >= 0; b--){ // bytes in decending order
                        ip_list_message->message[offset+b] |= ipad&0xFF; // set the byte
                        ipad >>= 8; // shift to next
                    }
                    offset+=4; // jump forward 4 bytes in the message
                    temp = temp->next; // get the next ip
                }
                // Add the new ip
                IPL_add(address.sin_addr.s_addr,&(meta->ip_list),temp_nick);
                meta->ip_count++;
                //
                unlock(meta);
                send_message_encrypted(ip_list_message, new_socket, meta);
                free(ip_list_message->message);
                free(ip_list_message);
                close(new_socket);
            }
            else if(message[0]==DISCONNECT){ // disconnect
                char* conn = calloc(100,1);
                char* temp_nick = IPL_contains(address.sin_addr.s_addr,meta->ip_list);
                strcat(conn,inet_ntoa(address.sin_addr));
                strcat(conn," (");
                strcat(conn,temp_nick);
                strcat(conn,") disconnected.\0");
                MSG_add(conn, "~", time(NULL), &(meta->messages));
                free(conn);
                free(temp_nick);
                IPL_remove(address.sin_addr.s_addr,&(meta->ip_list));
                meta->ip_count--;
                
                close(new_socket);
            }
            else if(message[0]==STD_MSG){ // normal message
                uint32_t t = 0;
                for(b = 3; b>=0; b--){
                    t |= message[1+MAXMSGLEN+b];
                    if(b!=0)
                        t<<=8;
                }
                char* nick = IPL_contains(address.sin_addr.s_addr,meta->ip_list);
                MSG_add((char*)(message+1),nick,t,&(meta->messages));
                free(nick);
                
                close(new_socket);
            }
            else if(message[0]==HELLO){ // new peer
                char temp_nick[20] = {0};
                for(c = 1; c <= 20; c++){
                    temp_nick[c-1] = message[c];
                }
                char* nick = IPL_contains(address.sin_addr.s_addr,meta->ip_list);
                if(!nick){
                    IPL_add(address.sin_addr.s_addr,&(meta->ip_list),temp_nick);
                    meta->ip_count++;
                }
                else
                    free(nick);
                close(new_socket);
            }
            else if(message[0]==BL_UPD){ // new ip to blacklist
                uint32_t address = 0;
                for(b = 3; b>=0; b--){ // each byte in address
                    address |= message[1+b]; // get the byte
                    if(b!=0) // shift if not the end byte
                        address <<= 8;
                }
                char* nick = IPL_contains(address,meta->blacklist);
                if(!nick){
                    IPL_add(address,&(meta->blacklist),"bad"); // add the ip to master list
                    meta->blacklist_count++;
                }
                else
                    free(nick);
                close(new_socket);
            }
            else if(message[0]==F_MSG){
                char* msg = calloc(100,1);
                char* nick = IPL_contains(address.sin_addr.s_addr,meta->ip_list);
                strcat(msg,"new file recieved: ");
                strcat(msg,(char*)(message+1));
                strcat(msg,". placed in files directory.\0");
                char path[1024] = {0};
                strcat(path, getenv("HOME"));
                strcat(path,"/.darksync/");
                strcat(path,(char*)(message+1));
                FILE* fp = fopen(path,"w");
                fwrite(message+261, 1, (int)*(message+257), fp);
                MSG_add(msg, nick, time(NULL), &(meta->messages));
                free(msg);
            }
            else{ // otherwise drop
                char* bad = calloc(100,1);
                strcat(bad, "WARNING: bad message from ");
                strcat(bad, inet_ntoa(address.sin_addr));
                strcat(bad, ". Dropping and blacklisting.\0");
                MSG_add(bad, "~", time(NULL), &(meta->messages));
                free(bad);
                
                IPL_add(address.sin_addr.s_addr,&(meta->blacklist),"bad");
                meta->blacklist_count++;
                meta->emit_black = 1;
                close(new_socket);
            }
            free(message);
        }
    }
    return 0;
}
char *fgets_wrapper(char *buffer, size_t buflen, FILE *fp)
{
    if (fgets(buffer, buflen, fp) != 0)
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        return buffer;
    }
    return 0;
}

void* message_sender_worker(void* arg){

    if(fork()>0) return;
    Metadata meta = (Metadata)arg;
    int c, b, i, ip, len;
    while(meta->lock!=2){
        if(meta->emit_black&&meta->ip_count>1){ // new blacklist item, send it to everyone
            //grab the most recent addition to the list
            IP_List temp = meta->ip_list;
            while(temp->next)
                temp = temp->next;
            uint32_t new_black = temp->ip;
            Message bl_message = calloc(1,sizeof(struct message_s));
            bl_message->identifier = BL_UPD;
            bl_message->size = 21; // ident and ip
            bl_message->message = calloc(20,1);
            int c, b, i, ip;
            for(b = 3; b >= 0; b--){ // bytes in decending order
                bl_message->message[b] |= new_black&0xFF; // set the byte
                new_black >>= 8; // shift to next
            }
            IP_List temp_ip = meta->ip_list->next;
            for(ip=1; ip < meta->ip_count; ip++){
                // connect to node
                struct sockaddr_in node;
                node.sin_family = AF_INET;
                node.sin_port = htons(RPORT);
                node.sin_addr.s_addr = temp_ip->ip;
                while(connect(meta->sender_s, (struct sockaddr *)&node, sizeof(node)) < 0);
                send_message_encrypted(bl_message, meta->sender_s, meta);
                close(meta->sender_s);
                meta->sender_s = init_socket(SPORT);
                temp_ip=temp_ip->next;
            }
            free(bl_message->message);
            free(bl_message);
        }
        char* message = calloc(MAXMSGLEN, 1);
        memset(message, 0, MAXMSGLEN);
        fgets_wrapper(message, MAXMSGLEN, stdin);
        if(message[0]=='/'&&message[1]=='q'&&message[2]=='\0'){
            // send disconnect
            if(meta->ip_count > 1){
                Message disconnect = calloc(1,sizeof(struct message_s));
                disconnect->identifier = DISCONNECT;
                disconnect->size = 1;
                IP_List temp_ip = meta->ip_list->next;
                for(ip = 1; ip < meta->ip_count; ip++){
                    struct sockaddr_in node;
                    node.sin_family = AF_INET;
                    node.sin_port = htons(RPORT);
                    node.sin_addr.s_addr = temp_ip->ip;
                    while(connect(meta->sender_s, (struct sockaddr *)&node,sizeof(node)) < 0);
                    send_message_encrypted(disconnect, meta->sender_s, meta);
                    close(meta->sender_s);
                    meta->sender_s = init_socket(SPORT);
                    temp_ip=temp_ip->next;
                }
                free(disconnect);
            }
            
            meta->lock = 2;
            shutdown(meta->reciever_s,SHUT_RDWR);
        }
        else if(message[0]=='/'&&message[1]=='l'&&message[2]=='\0'){
            char* mes = calloc(30+(20*(meta->ip_count)),1);
            strcat(mes,"Connected:\n");
            IP_List temp = meta->ip_list;
            while(temp){
                strcat(mes,"\t     ");
                strcat(mes,temp->nick);
                if(temp->next)
                    strcat(mes,"\n");
                temp = temp->next;
            }
            MSG_add(mes,"~",time(NULL),&meta->messages);
        }
        else if(message[0]=='/'&&message[1]=='k'&&message[2]=='\0'){
            generate_key_256();
            char* mes = "new key generated and placed in keys dir.";
            MSG_add(mes,"~",time(NULL),&meta->messages);
            
        }
        else if(message[0]=='/'&&message[1]=='h'&&message[2]=='\0'){
            char* mes = "/q: quit\n\t     /h: this message\n\t     /l: list online\n\t     /k: generate new key\n\t     /f [filename in .darksync/files]: send a file";
            MSG_add(mes,"~",time(NULL),&meta->messages);
        }
        else if(message[0]=='/'&&message[1]=='f'&&message[2]==' '){
	        //get file path
	        char fp[256] = {0};
            int pointer = 3;
            while((pointer-3)<256&&message[pointer]!='\0'){
                fp[pointer-3] = message[pointer];
                if(message[pointer]=='\0'){
                    break; // string name complete
                }
                pointer++;
            }
            if((pointer-3)==255){
            }
            else{
                char path[1024] = {0};
                strcat(path, getenv("HOME"));
                strcat(path,"/.darksync/");
                strcat(path,fp);
                FILE* fts = fopen(path,"r");
                if(!fts){

                }
                else{
                    fseek(fts, 0L, SEEK_END);
                    int sz = ftell(fts);
                    rewind(fts);
                }
            }
	    }
        else{ // normal message
            uint32_t t = (uint32_t)time(NULL);
            if(meta->ip_count > 1){
                Message mes = calloc(1,sizeof(struct message_s));
                mes->identifier = STD_MSG;
                mes->size = 1+MAXMSGLEN+4;
                mes->message = calloc(MAXMSGLEN+4,1);
                memcpy(mes->message,message,MAXMSGLEN);
                memcpy((mes->message)+MAXMSGLEN, &t, 4);
                // add message to messages
                char* temp_nick = calloc(20,1);
                memcpy(temp_nick, meta->nick, 20);
                MSG_add(message, temp_nick, t, &(meta->messages));
                free(temp_nick);
                IP_List temp_ip = meta->ip_list->next;
                for(ip = 1; ip < meta->ip_count; ip++){
                    struct sockaddr_in node;
                    node.sin_family = AF_INET;
                    node.sin_port = htons(RPORT);
                    node.sin_addr.s_addr = temp_ip->ip;
                    while(connect(meta->sender_s, (struct sockaddr *)&node,sizeof(node)) < 0);
                    send_message_encrypted(mes, meta->sender_s, meta);
                    close(meta->sender_s);
                    meta->sender_s = init_socket(SPORT);
                    temp_ip=temp_ip->next;
                }
                free(mes);
            }
        }
        free(message);
    }
    return 0;
}

// Locks
void lock(Metadata meta){
    while(meta->lock);
    meta->lock = 1;
}

void unlock(Metadata meta){
    meta->lock = 0;
}

// Destruction
void destructor(Arguments args, Metadata meta){
    if(args){
        free(args->key);
        free(args->node_ip);
        free(args->nickname);
        free(args);
    }
    if(meta){
        MSG_destroy(meta->messages);
        IPL_destroy(meta->ip_list);
        IPL_destroy(meta->blacklist);
        close(meta->reciever_s);
        close(meta->sender_s);
        free(meta->key);
        free(meta->iv);
        free(meta);
    }
}

int main(int argc, char* argv[]){
    if( argc != 5 )
        print_usage();
    else{
        // Check arguments
        check_args(argv);

        // Load arguments
        Arguments args = calloc(1, sizeof(struct arguments_s));
        args->key = calloc(1,strlen(argv[1])+1);
        args->node_ip = calloc(20,1);
        args->nickname = calloc(20,1);
        strncpy(args->key, argv[1], strlen(argv[1])+1);
        strncpy(args->nickname, argv[3], strlen(argv[3])+1);

        // Create Dirs
        create_directories();

        // Initialize Metadata
        Metadata meta = calloc(1,sizeof(struct metadata_s));
        memcpy(meta->nick,args->nickname,20);
        meta->ip_list = NULL;
        meta->blacklist = NULL;
        meta->messages = NULL;
        meta->emit_black = 0;
        meta->blacklist_count = 0;
        meta->encrypt_context = calloc(1,sizeof(struct AES_ctx));
        load_key(args->key,meta);
        load_blacklist(&meta->blacklist, meta);
        if(argv[2][0]=='p'){
            meta->ipassive = 1;
            strncpy(args->node_ip, "passive", 8);
        }
        else{
            strncpy(args->node_ip, argv[2], strlen(argv[2])+1);
            meta->ipassive = 0;
        }
        meta->ip_count = 1;
        meta->my_ip = getlocalip();
        if( !meta->my_ip ){
            fprintf(stderr,"%s is not a valid interface.\n",argv[4]);
            exit(EXIT_FAILURE);
        }
        IPL_add(meta->my_ip,&(meta->ip_list),meta->nick); //initial list only contains yourself
        meta->reciever_s = init_socket(RPORT);
        meta->sender_s = init_socket(SPORT);

        //for now derive from key
        memcpy(meta->iv,meta->key,16);
        // ask for the itial nodes ip list
        if(!meta->ipassive){
            // create the message;
            Message request = calloc(1,sizeof(struct message_s));
            request->identifier = ACTIVE_NODES_REQ;
            request->size = 1+20; // ident and nick
            request->message = malloc(20);
            memcpy(request->message,meta->nick,20);
            // connect to node
            struct sockaddr_in node;
            node.sin_family = AF_INET;
            node.sin_port = htons(RPORT);
            if(inet_pton(AF_INET, args->node_ip, &node.sin_addr)<=0){
                printf("\nInvalid address/ Address not supported \n");
                exit(EXIT_FAILURE);
            }
            while(connect(meta->sender_s, (struct sockaddr *)&node, sizeof(node)) < 0);
            send_message_encrypted(request, meta->sender_s, meta);
            free(request->message);
            free(request);
            int buf_len = (((MAXCONN*4)+2+20)/16)*16+(((MAXCONN*4)+2+20)%16)*16;
            uint8_t buffer[buf_len];
            int c, b, i, ip;
            for(i = 0; i < buf_len; i++)
                buffer[i] = 0;
            read(meta->sender_s, buffer, buf_len);
            AES_init_ctx_iv(meta->encrypt_context, meta->key, meta->iv);
            AES_CBC_decrypt_buffer(meta->encrypt_context,buffer,buf_len);
            uint8_t size = buffer[1];
            //extract nickname
            char temp_nick[20] = {0};
            for(c = 1; c <= 20; c++ ){
                temp_nick[c-1] = buffer[c+1];
            }
            //connection message
            char* conn = calloc(100,1);
            strcat(conn,inet_ntoa(node.sin_addr));
            strcat(conn," (");
            strcat(conn,temp_nick);
            strcat(conn,") connected.\0");
            MSG_add(conn,"~",time(NULL),&(meta->messages));
            free(conn);
            //add to ip list
            int ipad = 2+20;
            for(ipad = ipad; ipad < (size*4)+2+20; ipad+=4){ // for each ip address
                uint32_t address = 0;
                for(b = 0; b < 4; b++){ // each byte in address
                    address |= buffer[ipad+b]; // get the byte
                    if(b!=3) // shift if not the end byte
                        address <<= 8;
                }
                IPL_add(address,&(meta->ip_list),temp_nick); // add the ip to master list
                meta->ip_count++;
            }
            uint8_t black_size = buffer[ipad];
            ipad++;
            for(ipad = ipad; ipad < (size*4)+2+20+1+(black_size*4);ipad+=4){
                uint32_t address = 0;
                for(b = 0; b < 4; b++){ // each byte in address
                    address |= buffer[ipad+b]; // get the byte
                    if(b!=3) // shift if not the end byte
                        address <<= 8;
                }
                char* nick = IPL_contains(address,meta->blacklist);
                if(!nick){
                    IPL_add(address,&(meta->blacklist),"bad"); // add the ip to master list
                    meta->blacklist_count++;
                }
                else
                    free(nick);
            }
            //reinit socket
            close(meta->sender_s);
            meta->sender_s = init_socket(SPORT);
            // say hello
            request = calloc(1,sizeof(struct message_s));
            request->identifier = HELLO;
            request->size = 1+20; // ident and nick
            request->message = malloc(20);
            memcpy(request->message,meta->nick,20);
            IP_List temp = meta->ip_list->next;
            for(ip = 1; ip < meta->ip_count; ip++){
                // connect to node
                struct sockaddr_in node;
                node.sin_family = AF_INET;
                node.sin_port = htons(RPORT);
                node.sin_addr.s_addr = temp->ip;
                while(connect(meta->sender_s, (struct sockaddr *)&node, sizeof(node)) < 0);
                send_message_encrypted(request, meta->sender_s, meta);
                close(meta->sender_s);
                meta->sender_s = init_socket(SPORT);
                temp=temp->next;
            }
            free(request);
        }

        // Initialize Threads
        pthread_t thread_id_reciever, thread_id_sender;
        message_reciever_worker(meta);
        printf("%s\n", "forked reciever!");
        message_sender_worker(meta);
        printf("%s\n", "forked sender!");

        while(1) { sleep(100);}
        // Save the blacklist
        if(meta->blacklist)
            dump_blacklist(meta->blacklist);
        // Free the malloc
        destructor(args,meta);
    }
    return 0;
}
