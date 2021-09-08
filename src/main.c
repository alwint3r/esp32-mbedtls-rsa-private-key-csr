#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/oid.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/error.h"
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"

#define APP_LOGI(...) ESP_LOGI("APP", __VA_ARGS__)
#define APP_LOGE(...) ESP_LOGE("APP", __VA_ARGS__)

#define FORMAT_PEM 0
#define FORMAT_DER 1

#define DFL_TYPE MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE 2048
#define DFL_FILENAME "keyfile.key"
#define DFL_FORMAT FORMAT_PEM
#define DFL_MD_ALG MBEDTLS_MD_SHA256
#define DFL_SUBJECT_NAME "CN=wrover-dps-99,O=DycodeX,C=ID"

struct options
{
    int type;                 /* the type of key to generate          */
    int rsa_keysize;          /* length of key in bits                */
    const char *subject_name; /* subject name for certificate request */
    int format;               /* the output format to use             */
    mbedtls_md_type_t md_alg; /* Hash algorithm used for signature.   */
} opt;

void app_main()
{
    APP_LOGI("Hello world!");

    int ret = 1;
    mbedtls_pk_context key;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr req;
    const char *pers = "gen_key";

    int64_t us_start = esp_timer_get_time();

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);

    opt.type = DFL_TYPE;
    opt.rsa_keysize = DFL_RSA_KEYSIZE;
    opt.format = DFL_FORMAT;
    opt.md_alg = DFL_MD_ALG;
    opt.subject_name = DFL_SUBJECT_NAME;

    mbedtls_x509write_csr_set_md_alg(&req, opt.md_alg);

    APP_LOGI("Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        APP_LOGE("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);

        return;
    }

    APP_LOGI("Generating the private key!");

    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)opt.type))) != 0)
    {
        APP_LOGE("Failed. mbedtls_pk_setup_returned -0x%04x", -ret);

        return;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                              opt.rsa_keysize, 65537);
    if (ret != 0)
    {
        APP_LOGE("Failed. mbedtls_rsa_gen_key returned -0x%04x", -ret);
        return;
    }

    APP_LOGI("OK. Key information:");

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    if (mbedtls_rsa_check_pubkey(rsa) != 0)
    {
        APP_LOGE("RSA context does not contains public key!");
        goto cleanup;
    }

    if (mbedtls_rsa_check_privkey(rsa) != 0)
    {
        APP_LOGE("RSA context does not contain private key");
        goto cleanup;
    }

    unsigned char *pubkey_pem = (unsigned char *)malloc(1024);
    memset(pubkey_pem, 0, 1024);
    if (mbedtls_pk_write_pubkey_pem(&key, pubkey_pem, 1024) != 0)
    {
        APP_LOGE("Failed writing public key to string.");
        goto cleanup;
    }

    for (size_t i = 0; i < strlen((char*)pubkey_pem); i++)
    {
        printf("%c", pubkey_pem[i]);
    }

    free(pubkey_pem);

    printf("\r\n");

    unsigned char *privkey_pem = (unsigned char *)malloc(2048);
    memset(privkey_pem, 0, 2048);
    if (mbedtls_pk_write_key_pem(&key, privkey_pem, 2048) != 0)
    {
        APP_LOGE("Failed writing private key to string.");
        goto cleanup;
    }

    fflush(stdout);

    for (size_t i = 0; i < strlen((char*)privkey_pem); i++)
    {
        printf("%c", privkey_pem[i]);
    }
    printf("\r\n");

    free(privkey_pem);

    fflush(stdout);

    APP_LOGI("OK.");

    if ((ret = mbedtls_x509write_csr_set_subject_name(&req, opt.subject_name)) != 0)
    {
        APP_LOGE("Failed! mbedtls_x509write_csr_set_subject_name returned -0x%04x", -ret);
        goto cleanup;
    }

    mbedtls_x509write_csr_set_key(&req, &key);

    unsigned char *csr_pem = (unsigned char *)malloc(4096);
    memset(csr_pem, 0, 4096);
    if ((ret = mbedtls_x509write_csr_pem(&req, csr_pem, 4096, NULL, NULL)) != 0)
    {
        APP_LOGE("Failed! mbedtls_x509write_csr_pem returned -0x%04x", -ret);
        goto cleanup;
    }

    for (size_t i = 0; i < strlen((char*)csr_pem); i++)
    {
        printf("%c", csr_pem[i]);
    }
    printf("\r\n\r\n");

    free(csr_pem);

    int64_t us_end = esp_timer_get_time();

    uint64_t duration_ms = (uint64_t)((us_end - us_start) / 1000);

    APP_LOGI("duration: %llums", duration_ms);

cleanup:
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}