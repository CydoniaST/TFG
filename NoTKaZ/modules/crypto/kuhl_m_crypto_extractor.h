/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../../../modules/kull_m_cRyPTO.h"
#include "../../../modules/kull_m_memory.h"
#include "../../../modules/kull_m_ProCeSs.h"

void kuhl_m_cRyPTO_exTraCtor_capi32(PKULL_M_MEMORY_ADDRESS address);
void kuhl_m_cRyPTO_exTraCtor_bcrypt32(PKULL_M_MEMORY_ADDRESS address);
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
void kuhl_m_cRyPTO_exTraCtor_capi64(PKULL_M_MEMORY_ADDRESS address);
void kuhl_m_cRyPTO_exTraCtor_bcrypt64(PKULL_M_MEMORY_ADDRESS address);
#endif

DWORD kuhl_m_cRyPTO_exTraCtor_GetKeySizeForEncryptMemory(DWORD size);
DWORD kuhl_m_cRyPTO_exTraCtor_GetKeySize(DWORD bits);

NTSTATUS kuhl_m_cRyPTO_exTraCt(int argc, wchar_t * argv[]);

typedef struct _JlzW_CRYPTPROV {
	PVOID CPAcquireContext;
	PVOID CPReleaseContext;
	PVOID CPGenKey;
	PVOID CPDeriveKey;
	PVOID CPDestroyKey;
	PVOID CPSetKeyParam;
	PVOID CPGetKeyParam;
	PVOID CPExportKey;
	PVOID CPImportKey;
	PVOID CPEncrypt;
	PVOID CPDecrypt;
	PVOID CPCreateHash;
	PVOID CPHashData;
	PVOID CPHashSessionKey;
	PVOID CPDestroyHash;
	PVOID CPSignHash;
	PVOID CPVerifySignature;
	PVOID CPGenRandom;
	PVOID CPGetUserKey;
	PVOID CPSetProvParam;
	PVOID CPGetProvParam;
	PVOID CPSetHashParam;
	PVOID CPGetHashParam;
	PVOID unk0;
	PVOID CPDuplicateKey;
	PVOID CPDuplicateHash;
	PVOID unk1;
	PVOID ImageBase;
	PVOID obfUnk2;
} JlzW_CRYPTPROV, *PJlzW_CRYPTPROV;

typedef struct _JlzW_BCRYPT_GENERIC_KEY_HEADER {
	DWORD size;
	DWORD tag;	// 'MS*'
	DWORD type;
} JlzW_BCRYPT_GENERIC_KEY_HEADER, *PJlzW_BCRYPT_GENERIC_KEY_HEADER;

typedef struct _JlzW_BCRYPT_BIGNUM_Header {
	DWORD tag; // 6D4D0040h or 6D4D0000h for complex type, 67490000h for Int, 67440000h for Div (?)
	DWORD unkLen0; // (# of 16 bytes block?)
	DWORD size; // including this struct
	DWORD unk0; // align ?
} JlzW_BCRYPT_BIGNUM_Header, *PJlzW_BCRYPT_BIGNUM_Header;

typedef struct _JlzW_BCRYPT_BIGNUM_Div {
	JlzW_BCRYPT_BIGNUM_Header Header;
	DWORD unk0; // 0
	DWORD unk1; // 0
	DWORD unk2; // 6B41BC89h vary
	DWORD unk3; // 0
	JlzW_BCRYPT_BIGNUM_Header bn;
} JlzW_BCRYPT_BIGNUM_Div, *PJlzW_BCRYPT_BIGNUM_Div;

typedef struct _JlzW_PRIV_STRUCT_32 {
	DWORD32 strangeStruct;
	//DWORD unk0; // 0	// inconsitent between versions
	//DWORD unk1; // 0x20002
	//DWORD unk2; // 0x80119
	//DWORD32 rawKey;
	//DWORD unk3; // 4
	//DWORD unk4; // 0x2000e
	//DWORD unk5; // 0x8011b
} JlzW_PRIV_STRUCT_32, *PJlzW_PRIV_STRUCT_32;

typedef struct _JlzW_RAWKEY32 {
	DWORD32 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD32 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD32 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD32 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} JlzW_RAWKEY32, *PJlzW_RAWKEY32;

typedef struct _JlzW_RAWKEY_51_32 { // :(
	DWORD32 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD32 Data;
	DWORD unk1;
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD32 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} JlzW_RAWKEY_51_32, *PJlzW_RAWKEY_51_32;

typedef struct _JlzW_UNK_INT_KEY32 {
	DWORD32 /*PJlzW_RAWKEY */fPnkRawKey;
	DWORD unk0; // 2
} JlzW_UNK_INT_KEY32, *PJlzW_UNK_INT_KEY32;

typedef struct _JlzW_CRYPTKEY32 {
	DWORD32 CPGenKey;
	DWORD32 CPDeriveKey;
	DWORD32 CPDestroyKey;
	DWORD32 CPSetKeyParam;
	DWORD32 CPGetKeyParam;
	DWORD32 CPExportKey;
	DWORD32 CPImportKey;
	DWORD32 CPEncrypt;
	DWORD32 CPDecrypt;
	DWORD32 CPDuplicateKey;
	DWORD32 /*PJlzW_CRYPTPROV */fPnkProv;
	DWORD32 /*PJlzW_UNK_INT_KEY */obffPnkIntKey;
} JlzW_CRYPTKEY32, *PJlzW_CRYPTKEY32;


typedef struct _JlzW_BCRYPT_BIGNUM_Int32 {
	JlzW_BCRYPT_BIGNUM_Header Header;
	BYTE data[ANYSIZE_ARRAY];
} JlzW_BCRYPT_BIGNUM_Int32, *PJlzW_BCRYPT_BIGNUM_Int32;

typedef struct _JlzW_BCRYPT_BIGNUM_ComplexType32 {
	JlzW_BCRYPT_BIGNUM_Header Header;
	DWORD unkLenFlags0; // 0x80
	DWORD unk0; // 0
	BYTE unkArray0[8]; // 8Bh,9Ch,87h,0B9h,12h,68h,84h,7Fh vary
	DWORD32 unkDataAfter;
	DWORD unk1; // 0
	DWORD unk2; // 0
	DWORD unk3; // 0
	JlzW_BCRYPT_BIGNUM_Header bn;
} JlzW_BCRYPT_BIGNUM_ComplexType32, *PJlzW_BCRYPT_BIGNUM_ComplexType32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_DATA_10_32 {
	DWORD size; // 3552
	DWORD unk0; // 1
	DWORD len0; // 2048
	DWORD len1; // 2048
	DWORD unk1; // 0x10
	DWORD unk2; // 1
	DWORD unk3; // 0x11
	DWORD unk4; // 1
	DWORD unk5; // 2
	DWORD len2; // 1024
	DWORD len3; // 1024
	DWORD unk6;	// 8
	DWORD unk7;	// 8
	DWORD unk8;	// 8
	DWORD32 Prime1; // C
	DWORD32 Prime2; // C
	DWORD32 unkArray0;
	DWORD32 unkArray1;
	DWORD32 PublicExponent;
	DWORD32 PrivateExponent;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Modulus; // C
	DWORD32 _Prime1; // C
	DWORD32 _Prime2; // C
	DWORD32 _unkArray0;
	DWORD32 _unkArray1;
	DWORD32 _PublicExponent;
	DWORD32 _PrivateExponent;
	DWORD32 _Exponent1;
	DWORD32 _Exponent2;
	DWORD32 unk9; // 0 maybe align with data just after...
} JlzW_BCRYPT_ASYM_KEY_DATA_10_32, *PJlzW_BCRYPT_ASYM_KEY_DATA_10_32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_10_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits;
	DWORD unk0;
	DWORD32 unk1; // --> 'MSRA'
	DWORD32 data;
} JlzW_BCRYPT_ASYM_KEY_10_32, *PJlzW_BCRYPT_ASYM_KEY_10_32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_Bignum_81_32 {
	DWORD32 nbBlock; // ??? 16 ( 128 / 8)
	DWORD32 unk0; // 8
	DWORD32 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD32 unkLock0; // ...
	DWORD32 unkLock1; // 0
	DWORD32 unkLock2; // ...
	DWORD32 Prime;
	DWORD32 unkData0;
	DWORD32 unkData1;
	DWORD32 unkData2;
	DWORD32 unk3; // 0
	DWORD32 Bcrypt_modmul;
	DWORD32 unk4; // 0
	DWORD32 Bcrypt_modexp; // only 8.1
	DWORD32 unk5; // 0
} JlzW_BCRYPT_ASYM_KEY_Bignum_81_32, *PJlzW_BCRYPT_ASYM_KEY_Bignum_81_32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_81_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD32 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD32 PublicExponent;
	DWORD32 _PublicExponent;
	DWORD32 Modulus;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Coefficient;
	DWORD32 unk3;
	JlzW_BCRYPT_ASYM_KEY_Bignum_81_32 bnPrime1;
	JlzW_BCRYPT_ASYM_KEY_Bignum_81_32 bnPrime2;
} JlzW_BCRYPT_ASYM_KEY_81_32, *PJlzW_BCRYPT_ASYM_KEY_81_32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_Bignum_6_32 {
	DWORD32 nbBlock; // ??? 16 ( 128 / 8)
	DWORD32 unk0; // 8
	DWORD32 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD32 unkLock0; // ...
	DWORD32 unkLock1; // 0
	DWORD32 unkLock2; // ...
	DWORD32 Prime;
	DWORD32 unkData0;
	DWORD32 unkData1;
	DWORD32 unkData2;
	DWORD32 unk3; // 0
	DWORD32 Bcrypt_modmul;
	DWORD32 unk4; // 0
	//DWORD32 unk5; // 0
} JlzW_BCRYPT_ASYM_KEY_Bignum_6_32, *PJlzW_BCRYPT_ASYM_KEY_Bignum_6_32;

typedef struct _JlzW_BCRYPT_ASYM_KEY_6_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD32 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD32 PublicExponent;
	DWORD32 _PublicExponent;
	DWORD32 Modulus;
	DWORD32 Exponent1;
	DWORD32 Exponent2;
	DWORD32 Coefficient;
	DWORD32 unk3;
	JlzW_BCRYPT_ASYM_KEY_Bignum_6_32 bnPrime1;
	JlzW_BCRYPT_ASYM_KEY_Bignum_6_32 bnPrime2;
} JlzW_BCRYPT_ASYM_KEY_6_32, *PJlzW_BCRYPT_ASYM_KEY_6_32;

typedef struct _JlzW_BCRYPT_SYM_KEY_81_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // saMe as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD unk1; // bigalign?
	DWORD32 unk2; //--> 'MSRA'
	BYTE IV[16];
	DWORD dwData;
	BYTE Data[32];
	// ...
} JlzW_BCRYPT_SYM_KEY_81_32, *PJlzW_BCRYPT_SYM_KEY_81_32;

typedef struct _JlzW_BCRYPT_SYM_KEY_80_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // saMe as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD32 unk1; //--> 'MSRA'
	DWORD dwData;
	BYTE Data[64];
	BYTE IV[16];
	// ...
} JlzW_BCRYPT_SYM_KEY_80_32, *PJlzW_BCRYPT_SYM_KEY_80_32;

typedef struct _JlzW_BCRYPT_SYM_KEY_6_32 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD dwEffectiveKeyLen;
	DWORD dwData;
	BYTE Data[64];
	// ...
	BYTE IV[ANYSIZE_ARRAY /* dwBlockLen */];
} JlzW_BCRYPT_SYM_KEY_6_32, *PJlzW_BCRYPT_SYM_KEY_6_32;

typedef struct _JlzW_BCRYPT_HANDLE_KEY32 {
	DWORD size;
	DWORD tag;	// 'UUUR'
	DWORD32 hAlgorithm;
	DWORD32 key;
	DWORD32 unk0; // ?
} JlzW_BCRYPT_HANDLE_KEY32, *PJlzW_BCRYPT_HANDLE_KEY32;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64

typedef struct _JlzW_PRIV_STRUCT_64 {
	DWORD64 strangeStruct;
	//DWORD unk0; // 0	// inconsitent between versions
	//DWORD unk1; // 0x20002
	//DWORD unk2; // 0x80119
	//DWORD64 rawKey;
	//DWORD unk3; // 4
	//DWORD unk4; // 0x2000e
	//DWORD unk5; // 0x8011b
} JlzW_PRIV_STRUCT_64, *PJlzW_PRIV_STRUCT_64;

typedef struct _JlzW_RAWKEY64 {
	DWORD64 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD64 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD64 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD64 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} JlzW_RAWKEY64, *PJlzW_RAWKEY64;

typedef struct _JlzW_UNK_INT_KEY64 {
	DWORD64 /*PJlzW_RAWKEY */fPnkRawKey;
	DWORD unk0; // 2
} JlzW_UNK_INT_KEY64, *PJlzW_UNK_INT_KEY64;

typedef struct _JlzW_CRYPTKEY64 {
	DWORD64 CPGenKey;
	DWORD64 CPDeriveKey;
	DWORD64 CPDestroyKey;
	DWORD64 CPSetKeyParam;
	DWORD64 CPGetKeyParam;
	DWORD64 CPExportKey;
	DWORD64 CPImportKey;
	DWORD64 CPEncrypt;
	DWORD64 CPDecrypt;
	DWORD64 CPDuplicateKey;
	DWORD64 /*PJlzW_CRYPTPROV */fPnkProv;
	DWORD64 /*PJlzW_UNK_INT_KEY */obffPnkIntKey;
} JlzW_CRYPTKEY64, *PJlzW_CRYPTKEY64;


typedef struct _JlzW_BCRYPT_BIGNUM_Int64 {
	JlzW_BCRYPT_BIGNUM_Header Header;
	DWORD unk[4];
	BYTE data[ANYSIZE_ARRAY];
} JlzW_BCRYPT_BIGNUM_Int64, *PJlzW_BCRYPT_BIGNUM_Int64;

typedef struct _JlzW_BCRYPT_BIGNUM_ComplexType64 {
	JlzW_BCRYPT_BIGNUM_Header Header;
	DWORD unkLenFlags0; // 0x80
	DWORD unk0; // 0
	DWORD align0[2]; // tocheck ?
	BYTE unkArray0[8]; // 8Bh,9Ch,87h,0B9h,12h,68h,84h,7Fh vary
	DWORD64 unkDataAfter;
	DWORD unk1; // 0
	DWORD unk2; // 0
	DWORD unk3; // 0
	DWORD align1; // tocheck ?
	JlzW_BCRYPT_BIGNUM_Header bn;
} JlzW_BCRYPT_BIGNUM_ComplexType64, *PJlzW_BCRYPT_BIGNUM_ComplexType64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_DATA_10_64 {
	DWORD size; // 3552
	DWORD unk0; // 1
	DWORD len0; // 2048
	DWORD len1; // 2048
	DWORD unk1; // 0x10
	DWORD unk2; // 1
	DWORD unk3; // 0x11
	DWORD unk4; // 1
	DWORD unk5; // 2
	DWORD len2; // 1024
	DWORD len3; // 1024
	DWORD unk6;	// 8
	DWORD unk7;	// 8
	DWORD unk8;	// 8
	DWORD64 Prime1; // C
	DWORD64 Prime2; // C
	DWORD64 unkArray0;
	DWORD64 unkArray1;
	DWORD64 PublicExponent;
	DWORD64 PrivateExponent;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Modulus; // C
	DWORD64 _Prime1; // C
	DWORD64 _Prime2; // C
	DWORD64 _unkArray0;
	DWORD64 _unkArray1;
	DWORD64 _PublicExponent;
	DWORD64 _PrivateExponent;
	DWORD64 _Exponent1;
	DWORD64 _Exponent2;
	DWORD64 unk9; // 0 maybe align with data just after...
} JlzW_BCRYPT_ASYM_KEY_DATA_10_64, *PJlzW_BCRYPT_ASYM_KEY_DATA_10_64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_10_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits;
	DWORD unk0;
	DWORD64 unk1; // --> 'MSRA'
	DWORD64 data;
} JlzW_BCRYPT_ASYM_KEY_10_64, *PJlzW_BCRYPT_ASYM_KEY_10_64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_Bignum_81_64 {
	DWORD64 nbBlock; // ??? 16 ( 128 / 8)
	DWORD64 unk0; // 8
	DWORD64 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD64 unkLock0; // ...
	DWORD64 unkLock1; // 0
	DWORD64 unkLock2; // ...
	DWORD64 Prime;
	DWORD64 unkData0;
	DWORD64 unkData1;
	DWORD64 unkData2;
	DWORD64 unk3; // 0
	DWORD64 Bcrypt_modmul;
	DWORD64 unk4; // 0
	DWORD64 Bcrypt_modexp; // only 8.1
	DWORD64 unk5; // 0
} JlzW_BCRYPT_ASYM_KEY_Bignum_81_64, *PJlzW_BCRYPT_ASYM_KEY_Bignum_81_64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_81_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD64 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD64 PublicExponent;
	DWORD64 _PublicExponent;
	DWORD64 Modulus;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Coefficient;
	DWORD64 unk3;
	JlzW_BCRYPT_ASYM_KEY_Bignum_81_64 bnPrime1;
	JlzW_BCRYPT_ASYM_KEY_Bignum_81_64 bnPrime2;
} JlzW_BCRYPT_ASYM_KEY_81_64, *PJlzW_BCRYPT_ASYM_KEY_81_64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_Bignum_6_64 {
	DWORD64 nbBlock; // ??? 16 ( 128 / 8)
	DWORD64 unk0; // 8
	DWORD64 unk1; // 32
	DWORD bits; // 1024
	DWORD unk2; // 1
	DWORD64 unkLock0; // ...
	DWORD64 unkLock1; // 0
	DWORD64 unkLock2; // ...
	DWORD64 Prime;
	DWORD64 unkData0;
	DWORD64 unkData1;
	DWORD64 unkData2;
	DWORD64 unk3; // 0
	DWORD64 Bcrypt_modmul;
	DWORD64 unk4; // 0
	//DWORD64 unk5; // 0
} JlzW_BCRYPT_ASYM_KEY_Bignum_6_64, *PJlzW_BCRYPT_ASYM_KEY_Bignum_6_64;

typedef struct _JlzW_BCRYPT_ASYM_KEY_6_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD bits0;
	DWORD unk0; // 1 + align
	DWORD64 unk1; // --> 'MSRA'
	DWORD unk2; // 1
	DWORD bits1;
	DWORD nbModulus; // ??? 32 ( 256 / 8)
	DWORD nbExp1 ; // ??? 16 ( 128 / 8)
	DWORD nbExp2; // ??? 16 ( 128 / 8)
	DWORD Tag; // 'KASR' (RSA Key)
	DWORD Size; // 0x308 + align
	DWORD64 PublicExponent;
	DWORD64 _PublicExponent;
	DWORD64 Modulus;
	DWORD64 Exponent1;
	DWORD64 Exponent2;
	DWORD64 Coefficient;
	DWORD64 unk3;
	JlzW_BCRYPT_ASYM_KEY_Bignum_6_64 bnPrime1;
	JlzW_BCRYPT_ASYM_KEY_Bignum_6_64 bnPrime2;
} JlzW_BCRYPT_ASYM_KEY_6_64, *PJlzW_BCRYPT_ASYM_KEY_6_64;

typedef struct _JlzW_BCRYPT_SYM_KEY_81_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // saMe as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD unk1; // bigalign?
	DWORD64 unk2; //--> 'MSRA'
	BYTE IV[16];
	DWORD dwData;
	BYTE Data[32];
	// ...
} JlzW_BCRYPT_SYM_KEY_81_64, *PJlzW_BCRYPT_SYM_KEY_81_64;

typedef struct _JlzW_BCRYPT_SYM_KEY_80_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD unk0; // saMe as BL ?
	DWORD dwEffectiveKeyLen;
	DWORD64 unk1; //--> 'MSRA'
	DWORD dwData;
	BYTE Data[64];
	BYTE IV[16];
	// ...
} JlzW_BCRYPT_SYM_KEY_80_64, *PJlzW_BCRYPT_SYM_KEY_80_64;

typedef struct _JlzW_BCRYPT_SYM_KEY_6_64 {
	JlzW_BCRYPT_GENERIC_KEY_HEADER Header;
	DWORD dwMode;
	DWORD dwBlockLen;
	DWORD dwEffectiveKeyLen;
	DWORD dwData;
	BYTE Data[64];
	// ...
	BYTE IV[ANYSIZE_ARRAY /* dwBlockLen */];
} JlzW_BCRYPT_SYM_KEY_6_64, *PJlzW_BCRYPT_SYM_KEY_6_64;

typedef struct _JlzW_BCRYPT_HANDLE_KEY64 {
	DWORD size;
	DWORD tag;	// 'UUUR'
	DWORD64 hAlgorithm;
	DWORD64 key;
	DWORD64 unk0; // ?
} JlzW_BCRYPT_HANDLE_KEY64, *PJlzW_BCRYPT_HANDLE_KEY64;
#endif

#define RSAENH_KEY_32	0xe35a172c
#define DSSENH_KEY_32	0xa2491d83

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define RSAENH_KEY_64	0xe35a172cd96214a0
#define DSSENH_KEY_64	0xa2491d83d96214a0
#endif

typedef struct _JlzW_CRYPT_SEARCH {
	PKULL_M_MEMORY_HANDLE hMemory;
	WORD Machine;
	JlzW_CRYPTKEY32 ProcessfPnkCryptKey32;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	JlzW_CRYPTKEY64 ProcessfPnkCryptKey64;
#endif
	BOOL bAllProcessfPnkCryptKey;
	DWORD myPid;
	DWORD prevPid;
	DWORD currPid;
	PCUNICODE_STRING ProCeSsName;
} JlzW_CRYPT_SEARCH, *PJlzW_CRYPT_SEARCH;