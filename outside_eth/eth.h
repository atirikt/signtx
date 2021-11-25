#ifndef ETH_HEADER
#define ETH_HEADER

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../crypto/bip39.h"
#include "../crypto/bip32.h"
#include "../crypto/curves.h"
#include "../crypto/secp256k1.h"
#include "../crypto/sha2.h"
#include "../crypto/ecdsa.h"
#include "../crypto/ripemd160.h"
#include "../crypto/base58.h"
#include "../crypto/sha3.h"

/// Convert byte array to unit32_t
#define BYTE_ARRAY_TO_UINT32(x) (x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3])

/// Enum used to differentiate between a single val, string of bytes and list of strings during rlp decoding/encoding in raw eth byte array
typedef enum { NONE, STRING, LIST } seq_type;

/**
 * @brief Struct to store Unsigned Ethereum Transaction details.
 * 
 */
#pragma pack(1)
typedef struct
{
  uint8_t length_size[1];
  uint8_t length[4];

  uint8_t nonce_size[1];
  uint8_t nonce[32];

  uint8_t gas_price_size[1];
  uint8_t gas_price[32];

  uint8_t gas_limit_size[1];
  uint8_t gas_limit[32];

  uint8_t to_address[20];

  uint8_t value_size[1];
  uint8_t value[32];

  uint64_t payload_size;
  uint8_t *payload;

  uint8_t chain_id_size[1];
  uint8_t chain_id[4];

  uint8_t dummy_v[1];
  uint8_t dummy_r[1];
  uint8_t dummy_s[1];
} eth_unsigned_txn;

/**
 * @brief Struct to store Ethereum address type details.
 * 
 */
#pragma pack(1)
typedef struct
{
  uint8_t chain_index[4];
  uint8_t address_index[4];
} eth_address_type;

/**
 * @brief Struct to store Ethereum transaction metadata details.
 * 
 */
#pragma pack(1)
typedef struct
{
  uint8_t wallet_index[1];
  uint8_t purpose_index[4];
  uint8_t coin_index[4];
  uint8_t account_index[4];

  uint8_t input_count[1];
  eth_address_type *input;

  uint8_t output_count[1];
  eth_address_type *output;

  uint8_t change_count[1];
  eth_address_type *change;

  uint8_t transactionFees[4];

  uint8_t decimal[1];

  char token_name[8];

} eth_txn_metadata;

/**
 * @brief Convert byte array to hex char array.
 * 
 * @param bytes Pointer to byte array.
 * @param len Length of byte array.
 * @param hex_char char array to store results of the conversion.
 */
void byte_array_to_hex_char(uint8_t *bytes, uint32_t len, char *hex_char);

/**
 * @brief Convert hex char array to byte array.
 * 
 * @param hex_string Hex char array.
 * @param string_length Length of hex_string char array.
 * @param byte_array Pointer to a byte array instance to store the results of the conversion.
 */
void eth_hex_string_to_byte_array(const char *hex_string, uint32_t string_length, uint8_t *byte_array);

/**
 * @brief Convert decimal to byte array
 * 
 * @param dec Decimal uint64_t to convert
 * @param hex Pointer to byte array
 * @param len Length of the byte array
 * @return Number of bytes after conversion
 */
uint8_t eth_dec_to_hex(const uint64_t dec, uint8_t *hex, uint64_t len);

/**
 * @brief Converts bendian byte array to decimal uint64_t.
 * 
 * @param bytes Bendian byte array to convert.
 * @param len Length of the byte array.
 * @return Converted byte array to decimal.
 */
uint64_t bendian_byte_to_dec(const uint8_t *bytes, uint8_t len);

/**
 * @brief Convert hex char array to decimal.
 * 
 * @param source Hex char array.
 * @return Converted decimal uint64_t.
 */
uint64_t hex2dec(char *source);

/**
 * @brief Get the receivers address from eth_unsigned_txn instance.
 * 
 * @param eth_unsigned_txn_ptr Pointer to Unsigned transaction instance.
 * @param address  Byte array of receiver's address.
 */
void eth_get_to_address(eth_unsigned_txn *eth_unsigned_txn_ptr, uint8_t *address);

/**
 * @brief Get amount to be sent set in the eth_unsigned_txn instance
 * 
 * @param eth_unsigned_txn_ptr Pointer to Unsigned transaction instance.
 * @param value char array to store value.
 * @return 
 */
uint32_t eth_get_value(eth_unsigned_txn *eth_unsigned_txn_ptr, char *value);

/**
 * @brief Verifies the unsigned transaction.
 * 
 * @param eth_utxn_ptr Pointer to the eth_unsigned_txn instance.
 * @return integer value for valid and invalid transactions.
 * @retval 0 Valid
 * @retval 1 Chain Id size not 1 or Chain Id size not 1
 * @retval 2 Value is 0 when payload size is 0
 * @retval 3 Gas limit is 0
 * @retval 4 Gas Price is 0
 */
int eth_validate_unsigned_txn(eth_unsigned_txn *eth_utxn_ptr);

/**
 * @brief Convert byte array representation of unsigned transaction to eth_unsigned_txn.
 * 
 * @param eth_unsigned_txn_byte_array Byte array of unsigned transaction.
 * @param byte_array_len Length of byte array.
 * @param unsigned_txn_ptr Pointer to the eth_unsigned_txn instance to store the transaction details.
 * @return Status of conversion
 * @retval 0 Success
 * @retval -1 Failure
 */
int eth_byte_array_to_unsigned_txn(const uint8_t *eth_unsigned_txn_byte_array, 
                                    size_t byte_array_len,
                                    eth_unsigned_txn *unsigned_txn_ptr);

/**
 * @brief Signed unsigned byte array.
 * 
 * @param eth_unsigned_txn_byte_array Byte array of unsigned transaction.
 * @param eth_unsigned_txn_len length of unsigned transaction byte array.
 * @param transaction_metadata Pointer to eth_txn_metadata instance.
 * @param mnemonics char array of mnemonics.
 * @param passphrase char array of passphrase.
 * @param sig Byte array of signature to store the result of signing unsigned transaction byte array.
 */
int sig_unsigned_byte_array(const uint8_t *eth_unsigned_txn_byte_array,
  uint64_t eth_unsigned_txn_len,
  const eth_txn_metadata *transaction_metadata,
  const char *mnemonics,
  const char *passphrase, uint8_t *sig, 
  const eth_unsigned_txn *const unsigned_txn_ptr,
  int *outputlen);

void generate_bytearr_from_unsigned_struct(const eth_unsigned_txn *const unsigned_txn_ptr,
uint8_t *output, uint32_t *len);

#endif