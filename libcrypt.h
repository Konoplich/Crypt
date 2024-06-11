#define ERR_GAMMA_LEN -1
unsigned int init_crypt_lib();
int shennon(unsigned char *data, size_t data_size, unsigned char *gamma, size_t gamma_len);
void about(FILE* fp);

