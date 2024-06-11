#include <stdio.h>
#include <unistd.h>
#include "libcrypt.h"
#include <time.h>
#include <stdint.h> //int64_t тип
    
#define GAMMA_LEN 50

#define DATA_BUF_LEN 50


#define ERR_OPEN_STDERR 1
#define ERR_OPEN_STDOUT 2
#define ERR_OPEN_STDIN 3
#define ERR_PARAM 3
#define LEN_FILE_NAME 100
#define LEN_TIME_STAMP 25
#define ERR_READ_DATA 4
#define ERR_SHENNON 5
#define ERR_DATA_LEN 6
#define ERR_BUF_EVERFLOW 7
#define ERR_PARSE_GAMMA 8
#define ERR_SETUP_GAMMA 9
#define ERR_READ_GAMMA 10
#define ERR_GAMMA_OVERFLOW 11
#define ERR_GAMMA_READ 12
#define ERR_VALUE_GAMMA 13

#undef LOG
//#define LOG

#ifdef LOG
    #define LOG(str,...) printf(str,##__VA_ARGS__);
#else
    #define LOG(str,...) dumb();
#endif

#define SET_GAMMA_PARAM(S) (S |= 0x10)
#define SET_GAMMA_FILE(S) (S |= 0x01)
#define CHECK_GAMMA_SETUP_CONFLICT(S) (S==0x11)

void dumb(){};	    
void usage(const char *prg, FILE *fpstderr){
		fprintf(fpstderr, "Использование\n");
		fprintf(fpstderr, "Простой режим\n");
		fprintf(fpstderr, "%s\n", prg);
		fprintf(fpstderr, "Режим снятия/наложения защиты\n");
		fprintf(fpstderr, "%s [ключ]\n", prg);
		fprintf(fpstderr, "%s [файл] [ключ]\n", prg);
    
};
int main(int argc,char **argv)
{
    FILE *fpstderr = fdopen(STDERR_FILENO, "w");
    if(stderr==NULL)
    {
	exit(ERR_OPEN_STDERR);
    }

    if(init_crypt_lib()!=1)
    {
	fprintf(fpstderr, "Ошибка инициализации libcrypt\n");
	fclose(fpstderr);
	exit(ERR_OPEN_STDOUT);
    }


    FILE *fpstdout = fdopen(STDOUT_FILENO, "w");
    if(stdout==NULL)
    {
	fprintf(fpstderr, "Ошибка отtкрытия stdout\n");
	fclose(fpstderr);
	exit(ERR_OPEN_STDOUT);
    }
    fprintf(fpstdout, "test stdout\n"); //необходимо сбрасывать буфера, что бы увидеть сообщение

    //LOG("argc %d %s\n", argc, "test"); //debug
    LOG("argc %d\n", argc);

    size_t gamma_len = 0;    
    unsigned char gamma[GAMMA_LEN];
    FILE *fpstdin;

    int param;
    const char *data_filename=NULL;
    const char *gamma_filename=NULL;
    fflush(stdout);
    unsigned char setup_gamma = 0x00;
    while((param = getopt(argc, argv, "f:g:G:?")) != -1)
    {
	LOG("-%02X %c\n", param, param);
	switch(param)
	{
	    case 'f':
		data_filename = optarg;
		break;
	    case 'G':
		gamma_filename = optarg;
	        SET_GAMMA_FILE(setup_gamma);
		LOG("gamma_filename:%s\n", gamma_filename);
		break;
	    case 'g':
		SET_GAMMA_PARAM(setup_gamma);
		memset(gamma, 0x00, sizeof(gamma));
		LOG("gamma len %d, bufsize: %d\n", strlen(optarg), sizeof(gamma));
		size_t i=0;
		for(;optarg[i]!=0x00 && gamma_len < sizeof(gamma);i++)
		{
		    LOG("char %c %02x\n", optarg[i], optarg[i]);

		    switch((unsigned char)optarg[i])
		    {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			    gamma[gamma_len] |= (((unsigned char)optarg[i]) & 0x0F);
			    LOG("set gamma[%02x]=%02X\n", gamma_len, gamma[gamma_len]);
			    break;
			case 'a':
			case 'A':
			    break;
			    gamma[gamma_len] |= 0x0A;
			case 'b':
			case 'B':
			    gamma[gamma_len] |= 0x0B;
			    break;
			case 'c':
			case 'C':
			    break;
			    gamma[gamma_len] |= 0x0C;
			case 'd':
			case 'D':
			    break;
			    gamma[gamma_len] |= 0x0D;
			case 'e':
			case 'E':
			    gamma[gamma_len] |= 0x0E;
			    break;
			case 'f':
			case 'F':
			    gamma[gamma_len] |= 0x0F;
			default:
			    fprintf(fpstderr, "ошибка в gamma последовательности: %c hex: %02X\n"
				, optarg, optarg);
			    exit(ERR_PARSE_GAMMA);
		    }
		    if(!(i & 0x01)) //Четное
		    {
			gamma[gamma_len] <<= 4;
			LOG("<<gamma[%02x]=%02x\n", gamma_len, gamma[gamma_len]);
		    }else{
			gamma_len++;
		    }
		}
		if(i & 0x01)
		{
		    fprintf(fpstderr, "Ошибка в длине gamma\n");
		    exit(ERR_VALUE_GAMMA);
		}
		break;
	    case '?':
	    default:
		usage(argv[0], fpstderr);
		exit(ERR_PARAM);
	}
    }
    LOG("data_filename %s\n", data_filename);
    LOG("gamma_filename %s\n", gamma_filename);
    if(CHECK_GAMMA_SETUP_CONFLICT(setup_gamma))
    {
	sprintf(fpstderr, "Конфликтный параметры gamma\n");
	exit(ERR_SETUP_GAMMA);
    }
    if(setup_gamma == NULL)
    {
	LOG("gen gamma\n");
	srand(time(NULL));
	for(;gamma_len<GAMMA_LEN;gamma_len++)
	{
	    gamma[gamma_len] = rand() % 0xff;
	}
    }else if(gamma_filename != NULL){
	FILE *fpgamma= fopen(gamma_filename, "rb");
	if(fpgamma == NULL)
	{
	    fprintf(fpstderr, "Ошибка открытия файла gamma %s\n", gamma_filename);
	    exit(ERR_READ_GAMMA);
	}
	fseek(fpgamma, 0, SEEK_END);
	int64_t fsize = ftell(fpgamma);
	LOG("gamma file size: %x\n", fsize);
	if(fsize > sizeof(gamma))
	{
	    fprintf(fpstderr,"Переполнение буфера gamma %s\n", sizeof(gamma));
	    exit(ERR_GAMMA_OVERFLOW);
	}
	fseek(fpgamma, 0, SEEK_SET);
	size_t r = fread(gamma, sizeof(unsigned char), sizeof(gamma), fpgamma );
	LOG("read gamma %d\n", r);
	fclose(fpgamma);
	if(r != fsize)
	{
	    fprintf(fpstderr,"Ошибка чтения gamma %s\n");
	    exit(ERR_GAMMA_READ);
	}
	gamma_len = fsize;
    }

    if(data_filename != NULL){    
	fpstdin = fopen(data_filename, "r");
    }else{    
	fpstdin = fdopen(STDIN_FILENO, "rb");
    }

    if(fpstdin==NULL)
    {
        fprintf(fpstderr, "Ошибка отtкрытия файла\n");
        exit(ERR_OPEN_STDIN);
    }

    printf("Инициализация успешно\n");
    
    unsigned char data[DATA_BUF_LEN];
    size_t count = 0;
    ssize_t r;
    while(1)
    {
	unsigned char chr = fgetc(fpstdin);
	LOG("EOF %02X, chr %02X\n", EOF, chr);
	if(chr == (unsigned char)EOF )
	{
	    if(feof(fpstdin)) break;
	    fprintf(fpstderr, "Ошибка чтения\n");
	    exit(ERR_READ_DATA);
	}
	data[count] = chr;
	count++;
	if(count>DATA_BUF_LEN)
	{
	    LOG("buf len %d\n", count);
	    fprintf(fpstderr, "Буфер переполнен, дина %d\n", DATA_BUF_LEN); 
	    exit(ERR_BUF_EVERFLOW);
	}
    }

    fprintf(fpstdout, "crypt gamma:\n");
    LOG("len gamma %d\n", gamma_len);
    for(unsigned int i=0;i<gamma_len;i++)
    {
	fprintf(fpstdout,"%02X", gamma[i]);
    }
    if(count <= 0)
    {
	fflush(fpstdout);
	return ERR_DATA_LEN;
    }
    fprintf(fpstdout, "\ndata\n");
    for(unsigned int i=0;i<count;i++)
    {
	fprintf(fpstdout, "%02X", data[i]);
    }
    int res = shennon(&data, count, &gamma, gamma_len);
    if(res != count)
    {
	fprintf(fpstderr, "\nОшибка crypt %d\n", res);
	fflush(fpstdout);
	exit(ERR_SHENNON);
    }
    fprintf(fpstdout, "\nresult\n");
    for(unsigned int i=0;i<count;i++)
    {
	fprintf(fpstdout, "%02X", data[i]);
    }
    fprintf(fpstdout, "\n");

    char gamma_file[LEN_FILE_NAME] = "gamma_";
    char result_file[LEN_FILE_NAME] = "data_";
    
    time_t timebuf;
    struct tm *stm;
    time(&timebuf);
    stm = localtime(&timebuf);
    
    char timestamp[LEN_TIME_STAMP];
    snprintf(&timestamp, sizeof(timestamp),"%02d_%02d_%04d_%02d_%02d_%02d"
	    , stm->tm_mday, stm->tm_mon+1, stm->tm_year+1900
	    , stm->tm_hour, stm->tm_min, stm->tm_sec
	);
    strncat(&gamma_file, &timestamp, sizeof(gamma_file));
    strncat(&result_file, &timestamp, sizeof(result_file));
    LOG("%s\n", gamma_file);
    LOG("%s\n", result_file);
    
    FILE *fpgamma = fopen(gamma_file, "w");
    if(fpgamma==NULL)
    {
	fprintf(fpstderr, "Ошибка создания файла %s\n", gamma_file);
	exit(ERR_OPEN_STDIN);
    }

    size_t writen = 0;

    writen = fwrite(gamma, sizeof(unsigned char), gamma_len, fpgamma);
    if(writen != gamma_len){
	fprintf(fpstderr, "Ошибка записи файла %s\n", gamma_file);
	exit(ERR_OPEN_STDIN);	
    }
    fclose(fpgamma);

    FILE *fpdata = fopen(result_file, "w");
    if(fpdata==NULL)
    {
	fprintf(fpstderr, "Ошибка создания файла %s\n", result_file);
	exit(ERR_OPEN_STDIN);
    }

    writen = 0;

    writen = fwrite(data, sizeof(unsigned char), count, fpdata);
    if(writen != count){
	fprintf(fpstderr, "Ошибка записи файла %s\n", result_file);
	exit(ERR_OPEN_STDIN);	
    }
    fclose(fpdata);
    fprintf(fpstdout, "data:%s\ngamma:%s\n", result_file, gamma_file);
    fflush(fpstdout);
    return 0;
}