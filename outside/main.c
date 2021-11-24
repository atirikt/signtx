#include"btc.h"
#include<stdio.h>

void printGen(uint8_t *pu, size_t n){
  for(int i=0;i<n;i++){
    printf("%.2x", pu[i]);
  }
}

void printOut(signed_txn *Output){
  printGen(Output->network_version, sizeof(Output->network_version));
  printGen(Output->input_count, sizeof(Output->input_count));
  for(int i=0; i < Output->input_count[0]; i++){
    printGen(Output->input[i].previous_txn_hash, sizeof(Output->input->previous_txn_hash));
    printGen(Output->input[i].previous_output_index, sizeof(Output->input->previous_output_index));
    printGen(Output->input[i].script_length, sizeof(Output->input->script_length));
    printGen(Output->input[i].script_sig, 106);
    printGen(Output->input[i].sequence, sizeof(Output->input->sequence));
  }
  printGen(Output->output_count, sizeof(Output->output_count));
  for(int i=0; i < Output->output_count[0]; i++){
    printGen(Output->output[i].value, sizeof(Output->output->value));
    printGen(Output->output[i].script_length, sizeof(Output->output->script_length));
    printGen(Output->output[i].script_public_key, sizeof(Output->output->script_public_key));
  }
  printGen(Output->locktime, sizeof(Output->locktime));
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
    //convert_hex_dump_to_byte_array(unsigned_dump, hex_dump);
    
    signed_txn output={0};
    unsigned_txn intermediate={0};
    byte_array_to_unsigned_txn(hex_dump, &intermediate, strlen(hex_dump)/2);
    output.input = malloc(sizeof(*output.input)*intermediate.input_count[0]);
    output.output = malloc(sizeof(*output.output)*intermediate.output_count[0]);
    unsigned_txn_to_signed_txn(&intermediate, NULL, mnemonic, "", &output);
    printf("\nsigned dump:  ");
    printOut(&output);
    printf("\n\n\n");
    free(intermediate.input);
    free(intermediate.output);
    free(output.input);
    free(output.output);
  }
  return 0;
}