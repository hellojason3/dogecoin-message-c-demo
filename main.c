
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "rmd160.h"
#include "base58.h"

#include <secp256k1_recovery.h>
#define STRING_MAX_LEN 1000
#define LINE_MAX_LEN 5000
#define PATTERN "TT TT"
#define PATTERN_N 5
#define PATTERN_LEN 5
#define RMDsize 160

#define SHA256_HASH_SIZE 32


#define SIMPLE_ASSERT_WITH_TITLE(want, title) 	\
	do {			\
		if ((ret) != (want)) {            \
                printf("%s\n", title);                    \
		       	return (ret); 	\
		}			\
	}while(0)


//
char massage_prefix_doge[26] = {
        25, 68, 111, 103, 101, 99, 111, 105, 110, 32, 83, 105, 103, 110, 101, 100, 32, 77, 101, 115, 115, 97, 103, 101, 58, 10
};

struct String {
    char content[STRING_MAX_LEN];
    unsigned int length;
};

struct Data {
    struct String message;
    struct String public_key;
    struct String private_key;
    struct String address;
    struct String signature;

};


int *find_occurrences(char *text, char *target, int *count) {
    int len = strlen(text);
    int target_len = strlen(target);
    int *positions = malloc(sizeof(int) * len);
    int i, j, k;
    *count = 0;
    printf("len = %d, target_len = %d\n", len, target_len);
    for (i = 0; i <= len - target_len; i++) {
        if (text[i] == target[0]) {
            for (j = i, k = 0; k < target_len && text[j] == target[k]; j++, k++);
            if (k == target_len) {
                //printf("find in %d\n", i);
                positions[*count] = i;
                (*count)++;
            }
        }
    }

    if (*count == 0) {
        free(positions);
        return NULL;
    } else {
        return positions;
    }
}
int *find_substring(char *text, char *substring) {
    printf("text = %s\n", text);
    printf("find substring %s\n", substring);
    int count, i;
    int *positions = find_occurrences(text, substring, &count);

    if (positions == NULL) {
        printf("Substring not found.\n");
    } else {
        printf("Substring found %d times at positions: ", count);
        for (i = 0; i < count; i++) {
            printf("%d ", positions[i]);
        }
        printf("\n");
        //free(positions);
    }
    return positions;
}

int find_pattern_n(char* line, int* indexs) {
   int *positions = find_substring(line, PATTERN);
   if(positions == NULL) {
       printf("Substring not found.\n");
       return -1;
   }
   int i;
   int start = 0;
   int end = 0;
   for(i = 0; i < PATTERN_N; i++){
       start = end + PATTERN_LEN;
       end = positions[i];
       indexs[i * 2] = start;
       indexs[i * 2 + 1] = end;
   }
   indexs[0] = 0;
   indexs[PATTERN_N*2-1] = strlen(line);
   free(positions);
   return 0;
}

int parse_line_into_data(char* line, struct Data* data) {

    if(line == NULL) {
        printf("input line of data is NULL");
        return -1;
    }
    if (data == NULL) {
        printf("data struct is NULL");
        return -2;
    }

    int start = 0;
    int end = 0;
    int indexs[PATTERN_N * 2] = {0};

    char strings[PATTERN_N][STRING_MAX_LEN] = {0};
    int strings_each_len[PATTERN_N] = {0};
    //int *positions = find_substring(line, PATTERN);

    int ret = find_pattern_n(line, indexs);
    if(ret != 0) {
        printf("some thing wrong in parse_line_into_data");
        exit(-1);
    }

    for(int i = 0; i < 10; i++){
        printf("indexs = %d\n", indexs[i]);
    }
    //copy data from line to strings
    for(int i = 0, line_num = 0; i < PATTERN_N; i++, line_num ++) {
        start = indexs[i * 2];
        end = indexs[i * 2 + 1];
        strings_each_len[line_num] = end - start;

        for (int j = start, k = 0; j < end; j++, k++) {
            strings[line_num][k] = line[j];
        }
    }

    memcpy(&data->message.content, strings[0], strings_each_len[0]);

    memcpy(&data->public_key.content, strings[1], strings_each_len[1]);
    memcpy(&data->private_key.content, strings[2], strings_each_len[2]);
    memcpy(&data->address.content, strings[3], strings_each_len[3]);
    memcpy(&data->signature.content, strings[4], strings_each_len[4]);

    data->message.length = strings_each_len[0];
    data->public_key.length = strings_each_len[1];
    data->private_key.length = strings_each_len[2];
    data->address.length = strings_each_len[3];
    data->signature.length = strings_each_len[4];

    printf("memcpy address %s\n", data->address.content);
}
//
int read_file_to_data(char *file_name, struct Data **data_array, int *data_array_len){
    //init
    char line[LINE_MAX_LEN] = {0};
    *data_array_len = 0;

    //fp
    if(file_name == NULL) {
        printf("file pointer is null\n");
        return -1;
    }
    FILE *fp = fopen(file_name, "rb");
    if(fp == NULL) {
        printf("open file failed, file name = %s\n", file_name);
        return -1;
    }
    printf("file open success\n");
    //read
    int data_idx = 0;
    while(!feof(fp)) {
        fgets(line, LINE_MAX_LEN, fp);
        parse_line_into_data(line, &data_array[data_idx]);
        data_idx ++;
    }
    *data_array_len = data_idx;
    printf("finish read file\n");
    //close
    fclose(fp);
    return 0;
}
unsigned char* convert_char_array_into_unsigned(char* input, unsigned int len) {
    unsigned int array_size = len * (sizeof (unsigned char));
    unsigned char* u_char_array = malloc(array_size);
    if(u_char_array == NULL) {
        printf("malloc memory failed\n");
    }
    memcpy(u_char_array, input, array_size);
    return u_char_array;
}
void display_hex_array(unsigned char *arr, unsigned int len, char* title) {
    printf("hex_array len = %d, {%s} = ", len, title);
    printf("0x");
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", arr[i]);
    }
    printf("\n");
}

char* unsigned_char_into_char(unsigned char* input, unsigned int len) {
    char* output = malloc(sizeof(char) * len);
    unsigned int i = 0;
    for(i = 0; i < len; i++){
        output[i] = input[i];
    }
}

// message and prefix here are hex string
// note: the inputs of hash is hex string, not u8 array
unsigned char* magic_hash(char* message, char* msg_prefix) {
    unsigned int msg_len = strlen(message);
    unsigned int msg_prefix_len = strlen(msg_prefix);

    //Todo: it should be the same with vint in javascript
    unsigned int msg_VI_len = 0;
    if (msg_len < 65536 && msg_len >= 256) {
        msg_VI_len = 2;
    }else if (msg_len < 256) {
        msg_VI_len = 1;
    }else {
        msg_VI_len = 0;
    }


    if(msg_len == 0 || msg_prefix_len == 0 ) {
        printf("msg or prefix is NULL, msg_len=%d, pre_len=%d\n", msg_len, msg_prefix_len);
        return NULL;
    }

    unsigned char* u8_msg = convert_char_array_into_unsigned(message, msg_len);
    unsigned char* u8_mes_prefix = convert_char_array_into_unsigned(msg_prefix, msg_prefix_len);

    display_hex_array(u8_msg, msg_len, "msg");
    display_hex_array(u8_mes_prefix, msg_prefix_len, "msg_prefix");

    unsigned int total_len = msg_prefix_len + msg_VI_len + msg_len;
    unsigned char* total_message = malloc(sizeof(unsigned char) * (total_len));
    memset(total_message,0, total_len);

    unsigned int idx = 0;
    // copy prefix into total
    memcpy(&total_message[idx], u8_mes_prefix, msg_prefix_len);
    display_hex_array(total_message, total_len, "after copy prefix");

    idx += msg_prefix_len;
    total_message[idx] = msg_len;
    display_hex_array(total_message, total_len, "after copy msg_len");

    idx += msg_VI_len;
    memcpy(&total_message[idx], u8_msg, msg_len);
    display_hex_array(total_message, total_len, "after copy msg");

    unsigned char *first_round = SHA256(total_message, total_len);
    display_hex_array(first_round, SHA256_HASH_SIZE, "first round");

    unsigned char* hash = SHA256(first_round, SHA256_HASH_SIZE);
    display_hex_array(hash, SHA256_HASH_SIZE, "second round");

    free(first_round);
    free(u8_msg);
    free(u8_mes_prefix);
    free(total_message);

    return hash;
}


static int hex2int(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

void hexstr_to_bytes(const unsigned char* hexstr, unsigned char* bytes, int len) {
    int i;
    for (i = 0; i < len; i++) {
        int h = hex2int((char)hexstr[i * 2]);
        int l = hex2int((char)hexstr[i * 2 + 1]);
        if (h < 0 || l < 0) {
            break;
        }
        bytes[i] = (h << 4) | l;
    }
}

void convert_doge_signature_to_secp256k1(unsigned char* secp256k1_sig, const unsigned char* doge_sig) {

    unsigned char* doge_sig_hex = malloc(65);
    hexstr_to_bytes(doge_sig, doge_sig_hex, 65);
    display_hex_array(doge_sig_hex, 65, "doge signature hex");

    int i;
    for (i = 0; i < 64; i++) {
        secp256k1_sig[i] = doge_sig_hex[i+1];
    }
    secp256k1_sig[64] = doge_sig_hex[0] - 27;
    display_hex_array(secp256k1_sig, 65, "secp256k1 sig");

    free(doge_sig_hex);
}
unsigned char* recover_public_key(unsigned char* signature_doge, unsigned int signature_doge_len, unsigned char* magic_hash) {
    //create ctx
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    //note use SECP256K1_CONTEXT_NONE or SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN , don't change the result
    display_hex_array(signature_doge, signature_doge_len, "signature_doge input from file");

    secp256k1_pubkey pubkey_recover;  //64 bytes public key
    secp256k1_ecdsa_recoverable_signature sig_recover;

    //read doge signature from file, and convert it into u8 array
    convert_doge_signature_to_secp256k1(sig_recover.data, signature_doge);


    unsigned char* output64 = malloc(64);
    memset(output64, 0, 64);
    int recid = 0;
    int ret;

    //need convert to compact before recover, and all the operation in secp256k1 is based on compact, just serialize when display
    ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, output64, sig_recover.data, recid);
    if (!ret) {
        printf("cannot parse");
    }
    memcpy(sig_recover.data, output64, 64);

    display_hex_array(output64, 64, "output64");


    //recover
    display_hex_array(magic_hash, 32, "before recover magic hash");
    display_hex_array(sig_recover.data, 65, "before recover sig.data");
    ret = secp256k1_ecdsa_recover(ctx, &pubkey_recover, &sig_recover, magic_hash);
    if(ret != 1) {
        printf("recover failed\n");
    }
    display_hex_array(pubkey_recover.data, 64, "after recover pubkey");
    display_hex_array(sig_recover.data, 65, "after recover sig.data");
    display_hex_array(magic_hash, 32, "after recover magic hash");

    //compressed
    unsigned char* output = malloc(33);
    memset(output,0, 33);
    size_t output_len = 33;

    //serialize pubkey, compressed start with 02, uncompressed start with 04
    secp256k1_ec_pubkey_serialize(
            ctx, output, &output_len, &pubkey_recover, SECP256K1_EC_COMPRESSED);

    display_hex_array(pubkey_recover.data, 64, "after serialzed pubkey");
    display_hex_array(output, output_len, "after serialzed output");

    //destroy context
    secp256k1_context_destroy(ctx);

    unsigned char* public_key = malloc(33);
    memset(public_key, 0, 33);
    memcpy(public_key, output, 33);

    free(output64);
    free(output);
    return public_key;
}

unsigned char* RIPEMD160(unsigned char* message, unsigned int msg_len) {
    dword         MDbuf[RMDsize/32];   /* contains (A, B, C, D(, E))   */
    static byte   hashcode[RMDsize/8]; /* for final hash-value         */
    dword         X[16];               /* current 16-word chunk        */
    unsigned int  i;                   /* counter                      */
    dword         length;              /* length in bytes of message   */
    dword         nbytes;              /* # of bytes not yet processed */

    /* initialize */
    MDinit(MDbuf);
    length = msg_len;

    /* process message in 16-word chunks */
    for (nbytes=length; nbytes > 63; nbytes-=64) {
        for (i=0; i<16; i++) {
            X[i] = BYTES_TO_DWORD(message);
            message += 4;
        }
        compress(MDbuf, X);
    }                                    /* length mod 64 bytes left */

    /* finish: */
    MDfinish(MDbuf, message, length, 0);

    for (i=0; i<RMDsize/8; i+=4) {
        hashcode[i]   =  MDbuf[i>>2];         /* implicit cast to byte  */
        hashcode[i+1] = (MDbuf[i>>2] >>  8);  /*  extracts the 8 least  */
        hashcode[i+2] = (MDbuf[i>>2] >> 16);  /*  significant bits.     */
        hashcode[i+3] = (MDbuf[i>>2] >> 24);
    }

    return (byte *)hashcode;
}

unsigned char* hash_160(unsigned char* input, unsigned int input_len) {
    unsigned char* sha256 = SHA256(input, input_len);
    unsigned char* ripemd160 = RIPEMD160(sha256, SHA256_HASH_SIZE);

    display_hex_array(ripemd160, 20, "ripemd result =");

    free(sha256);
    return  ripemd160;
}

unsigned char* base58_check(unsigned char* input, unsigned int input_len, unsigned int *output_len) {
    unsigned char* output = malloc(50);
    memset(output, 0, 50);
    display_hex_array(input, input_len, "base58 input =");
    size_t bytes = base58_decode(input, input_len, output, 50);
    display_hex_array(output, 50, "base58 decode= ");
    unsigned char* ret = malloc(bytes);
    *output_len = bytes;
    memcpy(ret, &output[bytes], bytes);
    return ret;
}
int main() {
    printf("Hello, World!\n");
    int i, j, k, ret;
    struct Data datas[100] = {0};
    int datas_len = 0;
    unsigned int data_len ;

    //read file
    char file_name[100] = {"data.txt"};

    ret = read_file_to_data(file_name, datas, &datas_len);
    SIMPLE_ASSERT_WITH_TITLE(ret, "read file wrong");

    printf("read data len = %d\n", datas_len);
    for (i = 0; i < datas_len; i++){
        struct Data* tmp_data = &datas[i];
        printf("Struct data {%d} = \n", i);
        printf("   message = %s \n", tmp_data->message.content);
        printf("   public_key = %s \n", tmp_data->public_key.content);
        printf("   private_key = %s \n", tmp_data->private_key.content);
        printf("   address = %s \n", tmp_data->address.content);
        printf("   signature = %s \n", tmp_data->signature.content);
    }

    unsigned char* hash = magic_hash(datas[0].message.content, massage_prefix_doge);
    display_hex_array(hash, SHA256_HASH_SIZE, "hash result");
    //just for test
//    char pub_keys_jason[64] = {"3792157faf460776994c43eaadb41c5664c68dcaa00e549d1c8cf251bae8b0b0"};
//    unsigned char pub_keys_bytes[32];
//    hexstr_to_bytes(pub_keys_jason, pub_keys_bytes, 32);
//    display_hex_array(pub_keys_bytes, 32, "pub_keys_bytes ");
//    free(hash);
//    hash = pub_keys_bytes;

    unsigned char* public_key = recover_public_key(datas[0].signature.content, datas[0].signature.length, hash);
    display_hex_array(public_key, 33, "public key finally =");

    unsigned char* public_key_hash = hash_160(public_key, 33);
    display_hex_array(public_key_hash, 20, "public key hash");
    printf("datas[].len() %d\n", datas[0].address.length);

    unsigned char* payload = base58_check(datas[0].address.content, datas[0].address.length, &data_len);
    display_hex_array(payload, data_len, "payload = ");

    free(payload);
    free(public_key_hash);
    free(public_key);
    free(hash);
    return 0;
}
