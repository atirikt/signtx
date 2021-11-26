#include"eth.h"
#include<stdio.h>

void printGen(uint8_t *pu, size_t n){
  for(int i=0;i<n;i++){
    printf("%.2x", pu[i]);
  }
}

int hexchartoint(uint8_t ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
}
void updateDec(int *Out, int NewHex){
  int power = NewHex;
  for(int i = 99; i >=0;i--){
    int temp = Out[i]*16 + power;
    Out[i] = temp%10;
    power = temp/10;
  }
}
void convertbase16tobase10(size_t size_inp, char *u_Inp, int *Out){
  for(int i=0;i<size_inp;i++){
    updateDec(Out, hexchartoint(u_Inp[i]));
    //printf("%c\n", u_Inp[i]);
  }
  bool flag = true;
  for(int i=0;i<100;i++){
    if(!Out[i] && flag){
      continue;
    }
    flag = false;
    printf("%d", Out[i]);
  }
}

void getTokens(uint8_t *payload, uint8_t* tokens){
  strncpy(tokens, &payload[72], 64);
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
    //printf("%d", *intermediate.value_size);
    char valO[100]={0};
    for(int i=0;i<*intermediate.value_size;i++){
      snprintf(&valO[i*2],sizeof(valO),"%.2x",intermediate.value[i]);
    }
    int out[100]={0};
    convertbase16tobase10(*intermediate.value_size*2, valO,out);
    printf("wei \n");
    
    uint8_t tokens[32] = {0}, token_length = 0;
    char valT[1024]={0};
    for(int i=0;i<intermediate.payload_size;i++){
      snprintf(&valT[i*2],sizeof(valT),"%.2x",intermediate.payload[i]);
    }
    char *check="a9059cbb";
    char plsub[9]={0};
    strncpy(plsub,valT,8);

    if(!strcmp(plsub,check)){
      //this is a token transfer!!!!
      printf("\n tokens:  ");
      uint8_t tokens[100]={0};
      int out[100]={0};
      int token_length=0;
      getTokens(valT, tokens);
      //printf("%s %d",valT, intermediate.payload_size);
      convertbase16tobase10(64, tokens, out);
    }
    //printf("\n %d payload:  %s\n",intermediate.payload_size, valT);

    printf(" tokens \n");

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