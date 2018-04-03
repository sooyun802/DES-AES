#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>
#include <openssl/aes.h>

#define KEY_SIZE 16
#define K1_SIZE 8
#define BLOCK_SIZE 16
#define OUTPUT_SIZE 8

struct keyOutput {
	unsigned char key[KEY_SIZE];
	unsigned char output[OUTPUT_SIZE];
	unsigned char *password;
};

static unsigned char key1[20], key2[20];
static unsigned char plain[BLOCK_SIZE], cipher[32];
struct keyOutput *des_keyOutput, aes_keyOutput;
// passwordNum stores the number of all possbile keys
int passwordNum;

void DES(void);
void my_DES_encrypt(unsigned char *key, unsigned char *result);

void AES(void);
void my_AES_decrypt(const unsigned char *key, unsigned char *result);

int compare(const void *a, const void *b);
int my_strcmp(const unsigned char *s1, const unsigned char *s2);
void decode_Base64(const unsigned char *ciphertext);
int binarySearch(void);


int main(void) {
	FILE *fpIn, *fpOut;
	int i, j, k, flag = 1;
	unsigned char ch, tmp[30];

	memset(key1, 0, sizeof(key1));
	memset(key2, 0, sizeof(key2));
	memset(plain, 0, sizeof(plain));
	memset(cipher, 0, sizeof(cipher));
	
	fpIn = fopen("PlaintextCiphertext.txt", "r");
	des_keyOutput = (struct keyOutput*)malloc(sizeof(struct keyOutput) * 190000);

	// get 8 bytes of plain text
	for(i = 0; fscanf(fpIn, "%c", &ch) != EOF; ++i) {
		if(ch == '\n')
			break;
		if(i && i % 8 == 0)
			flag = 0;
		if(flag)
			plain[i] = ch;

	}

	// get 24 bytes of cipher text
	for(i = 0; fscanf(fpIn, "%c", &ch) != EOF; ++i) {
		if(i && i % 24 == 0) {\
			decode_Base64(tmp);
			break;
		}
		tmp[i] = ch;
	}

	fclose(fpIn);

	DES();
	AES();

	fpOut = fopen("keys.txt", "w");
	fprintf(fpOut, "%s\n%s", key1, key2);
	fclose(fpOut);

	for(i = 0; i < passwordNum; i++) {
		free(des_keyOutput[i].password);
	}
	free(des_keyOutput);

	return 0;
}

void DES(void) {
	FILE *fpIn;
	unsigned char buf[100], ch;
	int i, j, cnt = 0;

	/* passwords.txt contains the MD5 hash values of all the passwords */
	fpIn = fopen("passwords.txt", "r");
	for(i = 0; fscanf(fpIn, "%c", &ch) != EOF; ++i) {
		if(ch == '\n') {
			buf[i] = '\0';

			for(j = 0; j < K1_SIZE; j++) {
				if(isalpha(buf[j*2]))
					des_keyOutput[cnt].key[j] = (buf[j*2] - 'a' + 10) * 16;
				else
					des_keyOutput[cnt].key[j] = (buf[j*2] - '0') * 16;
				if(isalpha(buf[j*2+1]))
					des_keyOutput[cnt].key[j] += (buf[j*2+1] - 'a' + 10);
				else
					des_keyOutput[cnt].key[j] += (buf[j*2+1] - '0');
			}

			des_keyOutput[cnt].password = (unsigned char*)malloc(strlen(buf+33) + 1);
			memset(des_keyOutput[cnt].password, 0, sizeof(des_keyOutput[cnt].password));
			strncpy(des_keyOutput[cnt].password, buf+33, strlen(buf+33));
			
			/* encrypt the plain text with the DES method.
			   all possible keys wiil be used to encrypt.
			   the encrypted result of key 'des_keyOutput[cnt].key'
			   will be stored in 'des_keyOutput[cnt].output' */
			my_DES_encrypt(des_keyOutput[cnt].key, des_keyOutput[cnt].output);
			
			cnt++;
			i = -1;
			continue;
		}

		buf[i] = ch;
	}
	fclose(fpIn);

	passwordNum = cnt;

	// sort DES-encrypted results -> use for binary search
	qsort(des_keyOutput, cnt, sizeof(struct keyOutput), compare);
}

void my_DES_encrypt(unsigned char *key, unsigned char *result) {
	DES_cblock des_key, input;
	DES_key_schedule schedule;
	unsigned char tmp[8], output[8];
	int i;

	for(i = 0; i < 8; i++) {
		des_key[i] = key[i];
	}
	
	DES_set_key(&des_key, &schedule);
	
	for(i = 0; i < BLOCK_SIZE/2; i++) {
		input[i] = plain[i];
	}
	memset(output, 0, sizeof(output));
	DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);

	for(i = 0 ; i < OUTPUT_SIZE; i++) {
		result[i] = output[i];
	}
}

void AES(void) {
	FILE *fpIn;
	unsigned char buf[100], ch;
	int i, j, k, index;
	
	fpIn = fopen("passwords.txt", "r");
	aes_keyOutput.password = (unsigned char*)malloc(35);
	
	for(i = 0; fscanf(fpIn, "%c", &ch) != EOF; ++i) {
		if(ch == '\n') {
			buf[i] = '\0';
			for(j = 0; j < KEY_SIZE; j++) {
				if(isalpha(buf[j*2]))
					aes_keyOutput.key[j] = (buf[j*2] - 'a' + 10) * 16;
				else
					aes_keyOutput.key[j] = (buf[j*2] - '0') * 16;
				if(isalpha(buf[j*2+1]))
					aes_keyOutput.key[j] += (buf[j*2+1] - 'a' + 10);
				else
					aes_keyOutput.key[j] += (buf[j*2+1] - '0');
			}

			memset(aes_keyOutput.password, 0, 35);
			strncpy(aes_keyOutput.password, buf+33, strlen(buf+33));
			
			/* get decrypted result of cipher text and search (binary search)
			   through sorted array of encrypted results */
			my_AES_decrypt(aes_keyOutput.key, aes_keyOutput.output);
			
			/* use binary search the determine whether the AES-decrypted result
			   exists in the pool of DES-encrypted results of plain text */
			if((index = binarySearch()) != -1) {
				strcpy(key1, des_keyOutput[index].password);
				strcpy(key2, aes_keyOutput.password);
				break;
			}
			
			i = -1;
			continue;
		}

		buf[i] = ch;
	}
	fclose(fpIn);

	free(aes_keyOutput.password);
}

void my_AES_decrypt(const unsigned char *key, unsigned char *result) {
	unsigned char iv[AES_BLOCK_SIZE], aes_key[KEY_SIZE], aes_input[BLOCK_SIZE], aes_output[BLOCK_SIZE];
	AES_KEY dec_key;
	int i;
	
	// AES_inputs sizes "must" be multiples of 16
	for(i = 0; i < BLOCK_SIZE; i++) {
		aes_input[i] = cipher[i];
	}
	for(i = 0; i < KEY_SIZE; i++) {
		aes_key[i] = key[i];
	}

	memset(&dec_key, 0, sizeof(dec_key));
	memset(iv, 0x00, AES_BLOCK_SIZE);
	memset(aes_output, 0, sizeof(aes_output));
	AES_set_decrypt_key(aes_key, AES_BLOCK_SIZE*8, &dec_key);
	AES_cbc_encrypt(aes_input, aes_output, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);

	const unsigned char *p = (const unsigned char*)aes_output;
	for(i = 0; i < OUTPUT_SIZE; ++i) {
		result[i] = *p++;
	}
}

int binarySearch(void) {
	int low = 0, high = passwordNum - 1, mid;
	
	while(low <= high) {
		mid = (low + high) / 2;

		if(my_strcmp(aes_keyOutput.output, des_keyOutput[mid].output) < 0)
			high = mid - 1;
		else if(my_strcmp(aes_keyOutput.output, des_keyOutput[mid].output) > 0)
			low = mid + 1;
		else
			return mid;
	}

	return -1;
}

int compare(const void *a, const void *b) {
	struct keyOutput *tmp1 = (struct keyOutput*)a, *tmp2 = (struct keyOutput*)b; 
	return my_strcmp(tmp1->output, tmp2->output);
}

int my_strcmp(const unsigned char *s1, const unsigned char *s2) {
	int cnt = 0;

	while(cnt < 7 && *s1 < 256 && *s2 < 256 && *s1==*s2) {
		s1++;
		s2++;
		cnt++;
	}

	return (*s1 - *s2);
}

void decode_Base64(const unsigned char *ciphertext) {
	unsigned char buf[5], tmp;
	int i, j, k, cnt = 0;

	for(i = 0, k = 0; i < strlen(ciphertext) + 1; i++, k++) {
		if(i && i % 4 == 0) {
			for(j = 1; j < 4; j++) {
				cipher[cnt*3 + j-1] = buf[j-1] << (j*2);
				tmp = buf[j] >> (6 - j*2);
				cipher[cnt*3 + j-1] ^= tmp;
			}

			k = 0;
			cnt++;

			if(i == strlen(ciphertext))
				break;
		}

		if(isalpha(ciphertext[i])) {
			if(isupper(ciphertext[i]))
				buf[k] = ciphertext[i] - 'A';
			else
				buf[k] = ciphertext[i] - 'a' + 26;
		}
		else if(isalnum(ciphertext[i]))
			buf[k] = ciphertext[i] - '0' + 52;
		else if(ciphertext[i] == '+')
			buf[k] = 62;
		else if(ciphertext[i] == '/')
			buf[k] = 63;
		else
			buf[k] = 0;
	}
}
