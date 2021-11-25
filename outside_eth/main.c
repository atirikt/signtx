#include"eth.h"
#include<stdio.h>

void printGen(uint8_t *pu, size_t n){
  for(int i=0;i<n;i++){
    printf("%.2x", pu[i]);
  }
}


int main(){

  int t = 100;
  const char mnemonic[4096] = "cattle bachelor jazz edit raccoon quantum gasp chronic repair pipe cancel cover melt observe pink snake submit ripple pen visual brown price goddess shove";
  while(t--){
    uint8_t hex_dump[4096], unsigned_dump[4096], meta_dump[4096], passphrase[2048];
    printf("enter unsigned dump:  ");
    memset(hex_dump, 0x0, sizeof(hex_dump));
    memset(unsigned_dump, 0x0, sizeof(unsigned_dump));
    scanf("%s", hex_dump);
    
    eth_unsigned_txn intermediate={0};
    eth_byte_array_to_unsigned_txn(hex_dump, strlen(hex_dump)/2, &intermediate);
    
    printf("\n receipient address:  0x");
    for(int i = 0;i < 20;i++){
      printf("%.2x", intermediate.to_address[i]);
    }  
    printf("\n");
    
    printf("\n value:  ");
    uint64_t wei = 0;
    for(int i = 0; i < *intermediate.value_size; i++){
      wei <<= 8;
      wei |= intermediate.value[i];
    }
    printf("%llu wei \n", wei);
    

    uint8_t u_Byte[4096]={0};
    uint32_t len = 0;
    generate_bytearr_from_unsigned_struct(&intermediate, u_Byte, &len);

    uint8_t u_SigByte[4096] = {0};
    int outlength = 0;
    sig_unsigned_byte_array(u_Byte, len, NULL,mnemonic,"", u_SigByte, &intermediate, &outlength);
    
    printf("\nsigned dump:  ");
    printGen(u_SigByte, outlength);
    printf("\n\n\n");
    free(intermediate.payload);
  }
  return 0;
}