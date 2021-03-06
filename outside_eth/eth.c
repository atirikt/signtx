#include"eth.h"

void convert_hex_byte_to_decimal(uint8_t *btc_unsigned_txn_byte_array, const uint8_t *hex_dump){
	sscanf(hex_dump, "%2hhx", btc_unsigned_txn_byte_array);
}

void fillAndUpdate(uint8_t* u_Arr, size_t size, const uint8_t **inp, bool IsLength){
  for(int i = 0; i < size; i++){
		convert_hex_byte_to_decimal(&u_Arr[i], *inp);
    if(IsLength && u_Arr[i] <= 0x7f){
      *u_Arr = 1;
      return;
    }
    if(IsLength){
      if(u_Arr[i] >= 0x80 && u_Arr[i] <= 0xb7){
        u_Arr[i] -= 0x80;
      }else{
        //will happen only for payload in eth sign
        u_Arr[i] -= 0xb7;
      }
    }
		(*inp)+=2;
	}
}

int eth_byte_array_to_unsigned_txn(const uint8_t *eth_unsigned_txn_byte_array,
size_t byte_array_len,
eth_unsigned_txn *unsigned_txn_ptr){
  uint8_t lensize=0;
  convert_hex_byte_to_decimal(&lensize, eth_unsigned_txn_byte_array);
  if(lensize > 0xf7){
    *unsigned_txn_ptr->length_size = lensize - 0xf7;
    eth_unsigned_txn_byte_array += 2;
  }else{
    *unsigned_txn_ptr->length_size = 1;
  }

  uint8_t length_size = 1;
  //printf("\n%d", length_size);
  fillAndUpdate(unsigned_txn_ptr->length, *unsigned_txn_ptr->length_size, &eth_unsigned_txn_byte_array,false);
  
  fillAndUpdate(unsigned_txn_ptr->nonce_size, length_size, &eth_unsigned_txn_byte_array, true);
  fillAndUpdate(unsigned_txn_ptr->nonce, *unsigned_txn_ptr->nonce_size, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->gas_price_size, length_size, &eth_unsigned_txn_byte_array, true);
  fillAndUpdate(unsigned_txn_ptr->gas_price, *unsigned_txn_ptr->gas_price_size, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->gas_limit_size, length_size, &eth_unsigned_txn_byte_array, true);
  fillAndUpdate(unsigned_txn_ptr->gas_limit, *unsigned_txn_ptr->gas_limit_size, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->addr_length, 1, &eth_unsigned_txn_byte_array, true);
  fillAndUpdate(unsigned_txn_ptr->to_address, *unsigned_txn_ptr->addr_length, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->value_size, length_size, &eth_unsigned_txn_byte_array, true);
  fillAndUpdate(unsigned_txn_ptr->value, *unsigned_txn_ptr->value_size, &eth_unsigned_txn_byte_array, false);
  
  uint8_t ps;
  convert_hex_byte_to_decimal(&ps, eth_unsigned_txn_byte_array);
  //printf("\nps == %d\n", ps);
  if(ps > 0x7f){
    unsigned_txn_ptr->payload_len_of_len = 1;
    eth_unsigned_txn_byte_array+=2;
    if(ps > 0xb7){
      length_size = ps-0xb7;
      unsigned_txn_ptr->payload_len_of_len = length_size;
      uint8_t *temp = malloc(length_size);
      unsigned_txn_ptr->payload_size = 0;
      fillAndUpdate(temp, length_size, &eth_unsigned_txn_byte_array, false);
      for (int i=0;i<length_size;i++){
        unsigned_txn_ptr->payload_size <<=8;
        unsigned_txn_ptr->payload_size |= temp[i];
      }
      free(temp);
    }else{
      unsigned_txn_ptr->payload_size = ps-0x80;
    }
  }else{
    unsigned_txn_ptr->payload_len_of_len = 0;
    unsigned_txn_ptr->payload_size = 1;
  }

  unsigned_txn_ptr->payload = malloc(unsigned_txn_ptr->payload_size);
  fillAndUpdate(unsigned_txn_ptr->payload, unsigned_txn_ptr->payload_size, &eth_unsigned_txn_byte_array, false);

  *unsigned_txn_ptr->chain_id_size = 1;
  fillAndUpdate(unsigned_txn_ptr->chain_id, *unsigned_txn_ptr->chain_id_size, &eth_unsigned_txn_byte_array, false);

  //fillAndUpdate(unsigned_txn_ptr->dummy_v, 1, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->dummy_r, 1, &eth_unsigned_txn_byte_array, false);

  fillAndUpdate(unsigned_txn_ptr->dummy_s, 1, &eth_unsigned_txn_byte_array, false);

  return 0;
}

void attachAndUpdate(uint8_t **u_Out, size_t size, uint32_t *len, const uint8_t *u_Inp, bool putlength){
  uint8_t length;
  if(size == 1 && *u_Inp <=0x7f){
    putlength = false;
  }
  else{
    if(size >= 0 && size <= 55){
      length = size + 0x80;
    }else{
     length = size + 0xb7;
    }
  }
  if(putlength){
    memcpy(*u_Out, &length, 1);
    (*u_Out)++;
    (*len)++;
  }
  memcpy(*u_Out, u_Inp, size);
  (*len) = (*len) + size;
  *u_Out += size;
}

void generate_bytearr_from_unsigned_struct(const eth_unsigned_txn *const unsigned_txn_ptr,
uint8_t *output, uint32_t *len){
  int length_size = *unsigned_txn_ptr->length_size;
  if(length_size <= 55){
    length_size += 0xc0;
  }else{
    length_size += 0xf7;
  }
  attachAndUpdate(&output, *unsigned_txn_ptr->nonce_size, len, unsigned_txn_ptr->nonce, true);
  attachAndUpdate(&output, *unsigned_txn_ptr->gas_price_size, len, unsigned_txn_ptr->gas_price,true);
  attachAndUpdate(&output, *unsigned_txn_ptr->gas_limit_size, len, unsigned_txn_ptr->gas_limit,true);
  attachAndUpdate(&output, *unsigned_txn_ptr->addr_length, len, unsigned_txn_ptr->to_address,true);
  attachAndUpdate(&output, *unsigned_txn_ptr->value_size, len, unsigned_txn_ptr->value,true);
  if (unsigned_txn_ptr->payload_size > 55){
    uint8_t len_of_len = 0xb7+unsigned_txn_ptr->payload_len_of_len;
    *output = len_of_len;
    output++;
    (*len)++;
    uint8_t *temp = malloc(len_of_len), i =0;
    uint64_t ps = unsigned_txn_ptr->payload_size;
    while(ps > 0){
      temp[i] = ps & 0xff;
      ps >>= 8;
      i++;
    }
    for(int j = i-1; j >= 0; j--){
      *output = temp[j];
      output++;
      (*len)++;  
    }
    free(temp);
  }else if(!(unsigned_txn_ptr->payload_size == 1 && *unsigned_txn_ptr->payload <= 0x7f)){
    uint8_t length = 0x80 + unsigned_txn_ptr->payload_size;
    *output = length;
    output++;
    (*len)++;
  }
  attachAndUpdate(&output, unsigned_txn_ptr->payload_size, len, unsigned_txn_ptr->payload,false);
  attachAndUpdate(&output, *unsigned_txn_ptr->chain_id_size, len, unsigned_txn_ptr->chain_id,false);
  attachAndUpdate(&output, 1, len, unsigned_txn_ptr->dummy_r,false);
  attachAndUpdate(&output, 1, len, unsigned_txn_ptr->dummy_s,false);
}

int findParity(uint8_t *u_Arr, uint8_t len){
  int numOne = 0;
  for(int i=0;i<len;i++){
    uint8_t temp = u_Arr[i];
    while(temp > 0){
      if (temp & 0x1){
        numOne++;
      }
      temp >>=1;
    }
  }
  return numOne%2;
}

int sig_unsigned_byte_array(const uint8_t *eth_unsigned_txn_byte_array,
  uint64_t eth_unsigned_txn_len,
  const eth_txn_metadata *transaction_metadata,
  const char *mnemonics,
  const char *passphrase, uint8_t *sig, 
  const eth_unsigned_txn *const unsigned_txn_ptr,
  int *outputlen){
		HDNode z_WalletMeta = {0};
		uint8_t u_WalletSeed[64] = {0};

    mnemonic_to_seed(mnemonics, passphrase, u_WalletSeed, NULL);
    				
		//trezor API call
		//TBD: curve info unknown. ::added.
		if(!hdnode_from_seed(u_WalletSeed, 64, SECP256K1_NAME, &z_WalletMeta)){
			printf("err fun2 1");
			return 1;
		}

		if(!hdnode_private_ckd(&z_WalletMeta, 0x8000002c)){
			return 3;
		}
		if(!hdnode_private_ckd(&z_WalletMeta, 0x8000003c)){
			return 3;
		}
		if(!hdnode_private_ckd(&z_WalletMeta, 0x80000000)){
			return 3;
		}
		if(!hdnode_private_ckd(&z_WalletMeta, 0x00000000)){
			return 3;
		}
		if(!hdnode_private_ckd(&z_WalletMeta, 0x00000000)){
			return 3;
		}

		hdnode_fill_public_key(&z_WalletMeta);
    
    uint8_t u_Digest[32] = {0};
    keccak_256(eth_unsigned_txn_byte_array, eth_unsigned_txn_len,u_Digest);

    uint8_t u_Sig[64];
    if(ecdsa_sign_digest(&secp256k1, z_WalletMeta.private_key, u_Digest, u_Sig,NULL,NULL)){
			printf("err fun2 2");
			return 2;
		}
    uint32_t u_chain=0;
    for(int i=0;i<*unsigned_txn_ptr->chain_id_size;i++){
      u_chain <<= 8;
      u_chain |= unsigned_txn_ptr->chain_id[i];
    }
    
    uint8_t v = 35 + u_chain*2 + findParity(&u_Sig[32], 32); //fixed 1 byte
    //printf("\nv = %d\n",v);
    memcpy(sig,eth_unsigned_txn_byte_array, eth_unsigned_txn_len);
    int outputlength = eth_unsigned_txn_len - 2 - *unsigned_txn_ptr->chain_id_size;
    memcpy(&sig[outputlength],&v, 1);
    outputlength++;
    uint8_t srlen = 0x20+0x80;
    memcpy(&sig[outputlength], &srlen, 1);
    outputlength++;
    memcpy(&sig[outputlength], &u_Sig, 32);
    outputlength+=32;
    memcpy(&sig[outputlength], &srlen, 1);
    outputlength++;
    memcpy(&sig[outputlength], &u_Sig[32], 32);
    outputlength+=32;
    *outputlen = outputlength;
    uint8_t finalOut[4096], lengthtemp[4];
    int outtemp = outputlength, i = 0;
    
    while(outtemp > 0){
      lengthtemp[i] = outtemp & 0xff;
      outtemp >>= 8;
      i++;
    }

    //printf("i  :%d", i);
    int j=0;
    for(j = i-1; j >= 0; j--){
      finalOut[i-1-j+1] = lengthtemp[j];
    }
    finalOut[0] = 0xf7 + i;
    memcpy(&finalOut[i+1], sig, outputlength);
    (*outputlen) += i+1;

    memset(sig,0x0,*outputlen);
    //printf("\n output len: %d\n", *outputlen);
    if(*outputlen > 55){
      memcpy(sig, finalOut, *outputlen);
    }else{
      memcpy(sig, &finalOut[1], *outputlen);
      (*outputlen)--;
    }
    return 0;
}


