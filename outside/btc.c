/*
 File: btc.c
 brief: functionality to fill predefined structure with unsigned transaction and sign it.
*/

#include"btc.h"

extern const char SECP256K1_NAME[];

void convert_hex_byte_to_decimal(uint8_t *btc_unsigned_txn_byte_array, uint8_t *hex_dump){
	sscanf(hex_dump, "%2hhx", btc_unsigned_txn_byte_array);
}

void fillAndUpdate(uint8_t* u_Arr, size_t size, uint8_t **inp){
	for(int i = 0; i < size; i++){
		convert_hex_byte_to_decimal(&u_Arr[i], *inp);
		(*inp)+=2;
	}
}
//input :fig7 https://klmoney.wordpress.com/bitcoin-dissecting-transactions-part-2-building-a-transaction-by-hand/
void byte_array_to_unsigned_txn(uint8_t *btc_unsigned_txn_byte_array, unsigned_txn *unsigned_txn_ptr, int n){
	uint32_t i;
	//copy into structure defined incrementing ptr,do nothing else.
	//printf("%p %p", unsigned_txn_ptr->network_version, btc_unsigned_txn_byte_array);
	fillAndUpdate(unsigned_txn_ptr->network_version, sizeof(unsigned_txn_ptr->network_version), &btc_unsigned_txn_byte_array);
	fillAndUpdate(unsigned_txn_ptr->input_count, sizeof(unsigned_txn_ptr->input_count), &btc_unsigned_txn_byte_array);
	unsigned_txn_ptr->input = malloc(sizeof(*unsigned_txn_ptr->input)*unsigned_txn_ptr->input_count[0]);
    
	for(i=0; i < unsigned_txn_ptr->input_count[0]; i++)
	{
		fillAndUpdate(unsigned_txn_ptr->input[i].previous_txn_hash, sizeof(unsigned_txn_ptr->input[i].previous_txn_hash), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->input[i].previous_output_index, sizeof(unsigned_txn_ptr->input[i].previous_output_index), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->input[i].script_length, sizeof(unsigned_txn_ptr->input[i].script_length), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->input[i].script_public_key, sizeof(unsigned_txn_ptr->input[i].script_public_key), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->input[i].sequence, sizeof(unsigned_txn_ptr->input[i].sequence), &btc_unsigned_txn_byte_array);
	}
	fillAndUpdate(unsigned_txn_ptr->output_count, sizeof(unsigned_txn_ptr->output_count), &btc_unsigned_txn_byte_array);
	unsigned_txn_ptr->output = malloc(sizeof(*unsigned_txn_ptr->output)*unsigned_txn_ptr->output_count[0]);
  
	for(i=0; i < unsigned_txn_ptr->output_count[0]; i++)
	{
		fillAndUpdate(unsigned_txn_ptr->output[i].value, sizeof(unsigned_txn_ptr->output[i].value), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->output[i].script_length, sizeof(unsigned_txn_ptr->output[i].script_length), &btc_unsigned_txn_byte_array);
		fillAndUpdate(unsigned_txn_ptr->output[i].script_public_key, sizeof(unsigned_txn_ptr->output[i].script_public_key), &btc_unsigned_txn_byte_array);
	}
	fillAndUpdate(unsigned_txn_ptr->locktime, sizeof(unsigned_txn_ptr->locktime), &btc_unsigned_txn_byte_array);
	fillAndUpdate(unsigned_txn_ptr->sighash, sizeof(unsigned_txn_ptr->sighash), &btc_unsigned_txn_byte_array);
	//printf("3. %d", unsigned_txn_ptr->output[0].value[5]);

}

extern const ecdsa_curve secp256k1;
//get signed tx. returns signed transaction in signed_txn_ptr,
//caller responsible for allocating(and freeing) memory.
uint32_t unsigned_txn_to_signed_txn(const unsigned_txn *const unsigned_txn_ptr,
	txn_metadata *txn_metadata_ptr,
	const char *mnemonic,
	const char *passphrase,
  signed_txn * signed_txn_ptr){
		HDNode z_WalletMeta = {0};
		uint8_t u_WalletSeed[64] = {0};
		//trezor API call
		mnemonic_to_seed(mnemonic, passphrase, u_WalletSeed, NULL);
		
		//trezor API call
		//TBD: curve info unknown. ::added.

		if(!hdnode_from_seed(u_WalletSeed, 64, SECP256K1_NAME, &z_WalletMeta)){
			printf("err fun2 1");
			return 1;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x800002c)){
			return 3;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x8000001)){
			return 3;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x8000000)){
			return 3;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x0000000)){
			return 3;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x0000000)){
			return 3;
		}

		hdnode_fill_public_key(&z_WalletMeta);

		//public and private key should be known here.

		//double hash tx message(unsigned).
		uint8_t u_ShaInput[4096] = {0};
		uint8_t *pu_ShaInput = u_ShaInput;
		size_t size_inp = 0;
		//deep copy

		memcpy(pu_ShaInput, unsigned_txn_ptr->network_version, sizeof(unsigned_txn_ptr->network_version));
		pu_ShaInput += sizeof(unsigned_txn_ptr->network_version);
		size_inp += sizeof(unsigned_txn_ptr->network_version);
		
		memcpy(pu_ShaInput, unsigned_txn_ptr->input_count, sizeof(unsigned_txn_ptr->input_count));
		pu_ShaInput += sizeof(unsigned_txn_ptr->input_count);
		size_inp += sizeof(unsigned_txn_ptr->input_count);
		
		for(int i = 0; i < unsigned_txn_ptr->input_count[0]; i++){
			memcpy(pu_ShaInput, unsigned_txn_ptr->input[i].previous_txn_hash, sizeof(unsigned_txn_ptr->input[i].previous_txn_hash));
			pu_ShaInput += sizeof(unsigned_txn_ptr->input[i].previous_txn_hash);
			size_inp += sizeof(unsigned_txn_ptr->input[i].previous_txn_hash);

			memcpy(pu_ShaInput, unsigned_txn_ptr->input[i].previous_output_index, sizeof(unsigned_txn_ptr->input[i].previous_output_index));
			pu_ShaInput += sizeof(unsigned_txn_ptr->input[i].previous_output_index);
			size_inp += sizeof(unsigned_txn_ptr->input[i].previous_output_index);

			memcpy(pu_ShaInput, unsigned_txn_ptr->input[i].script_length, sizeof(unsigned_txn_ptr->input[i].script_length));
			pu_ShaInput += sizeof(unsigned_txn_ptr->input[i].script_length);
			size_inp += sizeof(unsigned_txn_ptr->input[i].script_length);

			memcpy(pu_ShaInput, unsigned_txn_ptr->input[i].script_public_key, sizeof(unsigned_txn_ptr->input[i].script_public_key));
			pu_ShaInput += sizeof(unsigned_txn_ptr->input[i].script_public_key);
			size_inp += sizeof(unsigned_txn_ptr->input[i].script_public_key);

			memcpy(pu_ShaInput, unsigned_txn_ptr->input[i].sequence, sizeof(unsigned_txn_ptr->input[i].sequence));
			pu_ShaInput += sizeof(unsigned_txn_ptr->input[i].sequence);
			size_inp += sizeof(unsigned_txn_ptr->input[i].sequence);
		}
		memcpy(pu_ShaInput, unsigned_txn_ptr->output_count, sizeof(unsigned_txn_ptr->output_count));
		pu_ShaInput += sizeof(unsigned_txn_ptr->output_count);
		size_inp += sizeof(unsigned_txn_ptr->output_count);
		
		for(int i = 0; i < unsigned_txn_ptr->output_count[0]; i++){
			memcpy(pu_ShaInput, unsigned_txn_ptr->output[i].value, sizeof(unsigned_txn_ptr->output[i].value));
			pu_ShaInput += sizeof(unsigned_txn_ptr->output[i].value);
			size_inp += sizeof(unsigned_txn_ptr->output[i].value);

			memcpy(pu_ShaInput, unsigned_txn_ptr->output[i].script_length, sizeof(unsigned_txn_ptr->output[i].script_length));
			pu_ShaInput += sizeof(unsigned_txn_ptr->output[i].script_length);
			size_inp += sizeof(unsigned_txn_ptr->output[i].script_length);

			memcpy(pu_ShaInput, unsigned_txn_ptr->output[i].script_public_key, sizeof(unsigned_txn_ptr->output[i].script_public_key));
			pu_ShaInput += sizeof(unsigned_txn_ptr->output[i].script_public_key);
			size_inp += sizeof(unsigned_txn_ptr->output[i].script_public_key);
		}
		memcpy(pu_ShaInput, unsigned_txn_ptr->locktime, sizeof(unsigned_txn_ptr->locktime));
		pu_ShaInput += sizeof(unsigned_txn_ptr->locktime);
		size_inp += sizeof(unsigned_txn_ptr->locktime);

		memcpy(pu_ShaInput, unsigned_txn_ptr->sighash, sizeof(unsigned_txn_ptr->sighash));
		size_inp += sizeof(unsigned_txn_ptr->sighash);

		uint8_t shaFinal[SHA256_DIGEST_LENGTH], shaFinal2[SHA256_DIGEST_LENGTH];
		sha256_Raw(u_ShaInput, size_inp, shaFinal);
		sha256_Raw(shaFinal, sizeof(shaFinal), shaFinal2);

		//call ecdsa with priv key from WalletMeta
		uint8_t u_Sig[64];
		
		if(ecdsa_sign_digest(&secp256k1, z_WalletMeta.private_key, shaFinal2, u_Sig,NULL,NULL)){
			printf("err fun2 2");
			return 2;
		}

		//form scriptsig, figure 8.(R, S) outputted from ecdsa.
		uint8_t u_ScriptSig[128] = {0}; // 106 for scriptsig including '\0'
		u_ScriptSig[0] = 0x47;
		u_ScriptSig[1] = 0x30;
		u_ScriptSig[2] = 0x44;
		u_ScriptSig[3] = 0x02;
		u_ScriptSig[4] = 0x20;
		memcpy(&u_ScriptSig[5], u_Sig, 32);
		u_ScriptSig[37] = 0x02;
		u_ScriptSig[38] = 0x20;		
		memcpy(&u_ScriptSig[39], &u_Sig[32], 32);
		u_ScriptSig[71] = 0x01;
		u_ScriptSig[72] = 0x21;
		//public_key is 33 B,assuming 0x03 is appended.
		memcpy(&u_ScriptSig[73], z_WalletMeta.public_key, sizeof(z_WalletMeta.public_key));
		//copy all unsigned except replace scriptpubkey prev with current script sig
		

		memcpy(signed_txn_ptr->network_version, unsigned_txn_ptr->network_version, sizeof(unsigned_txn_ptr->network_version));
		memcpy(signed_txn_ptr->input_count, unsigned_txn_ptr->input_count, sizeof(unsigned_txn_ptr->input_count));
		for(int i=0;i<signed_txn_ptr->input_count[0];i++){
			memcpy(signed_txn_ptr->input[i].previous_txn_hash, unsigned_txn_ptr->input[i].previous_txn_hash, sizeof(unsigned_txn_ptr->input[i].previous_txn_hash));
			memcpy(signed_txn_ptr->input[i].previous_output_index, unsigned_txn_ptr->input[i].previous_output_index, sizeof(unsigned_txn_ptr->input[i].previous_output_index));
			signed_txn_ptr->input[i].script_length[0] = 0x6a;
			memcpy(signed_txn_ptr->input[i].script_sig, u_ScriptSig, sizeof(signed_txn_ptr->input[i].script_sig));
			memcpy(signed_txn_ptr->input[i].sequence, unsigned_txn_ptr->input[i].sequence, sizeof(signed_txn_ptr->input[i].sequence));
		}
		memcpy(signed_txn_ptr->output_count, unsigned_txn_ptr->output_count, sizeof(unsigned_txn_ptr->output_count));
		for(int i=0; i < signed_txn_ptr->output_count[0]; i++){
			memcpy(signed_txn_ptr->output[i].value, unsigned_txn_ptr->output[i].value, sizeof(unsigned_txn_ptr->output[i].value));
			memcpy(signed_txn_ptr->output[i].script_length, unsigned_txn_ptr->output[i].script_length, sizeof(unsigned_txn_ptr->output[i].script_length));
			memcpy(signed_txn_ptr->output[i].script_public_key, unsigned_txn_ptr->output[i].script_public_key, sizeof(unsigned_txn_ptr->output[i].script_public_key));
		}
		//printf("3. %d", unsigned_txn_ptr->output[0].value[5]);

		memcpy(signed_txn_ptr->locktime, unsigned_txn_ptr->locktime, sizeof(*unsigned_txn_ptr->locktime));
		return 0;
}