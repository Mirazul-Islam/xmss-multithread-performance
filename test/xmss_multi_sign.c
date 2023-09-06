#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"
#include "../thpool.h"

#define XMSS_VERIFICATION_THREADS_START 1
#define XMSS_VERIFICATION_THREADS_LIMIT 16


#ifdef XMSSMT
#define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#define XMSS_SIGN_OPEN xmss_sign_open
#endif

#ifndef XMSS_VARIANT
#ifdef XMSSMT
#define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
#define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif
#endif

// Define data structure to pass multiple arguments to thread
typedef struct {
    unsigned char *pk;
    unsigned char *sm;
    unsigned long long smlen;
    unsigned char *mout;
    unsigned long long *mlen;
} verify_data;

// Function which will be run in each thread to verify signatur
void *verify_thread(void *arg)
{
    verify_data *data = (verify_data *) arg;
    XMSS_SIGN_OPEN(data->mout, data->mlen, data->sm, data->smleata->pk);
}

int main()
{
    // Define different message lengths
    unsigned long long mlen_values[] = {1024};
    int mlen_values_count = sizeof(mlen_values)/sizeof(mlen_val0]);

    for(int j = 0; j < mlen_values_count; j++)
    {
        unsigned long long int mlen = mlen_values[j];

        xmss_params params;
        uint32_t oid;

        if (XMSS_STR_TO_OID(&oid, XMSS_VARIANT)) {
#ifdef XMSSMT
            printf("XMSSMT variant %s not recognized!\n", XMSS_ANT);
#else
            printf("XMSS variant %s not recognized!\n", XMSS_VAT);
#endif
            return -1;
        }

        XMSS_PARSE_OID(&params, oid);
        unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
        unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
        unsigned char *m = malloc(mlen);
        unsigned char *sm = malloc(params.sig_bytes + mlen);
        unsigned char *mout = malloc(params.sig_bytes + mlen);
        unsigned long long smlen;

        randombytes(m, mlen);
        XMSS_KEYPAIR(pk, sk, oid);
        XMSS_SIGN(sk, sm, &smlen, m, mlen);

        for (int num_threads = XMSS_VERIFICATION_THREADS_START;_threads <=
                                                               S_VERIFICATION_THREADS_LIMIT; num_threads++)
        {
            threadpool thpool = thpool_init(num_threads);  // Ialize threadpool with current number of threads

            printf("Current mlen: %llu, current number of threa%d\n", mlen, num_threads);
            struct timeval start, end;

            gettimeofday(&start, NULL);
            verify_data verify_args[num_threads];
            for(int i = 0; i < num_threads; i++)
            {
                verify_data *this_arg = &verify_args[i];
                this_arg->pk = pk;
                this_arg->sm = sm;
                this_arg->smlen = smlen;
                this_arg->mout = mout;
                this_arg->mlen = &mlen;

                thpool_add_work(thpool, verify_thread, (void *)_arg);
            }


            thpool_wait(thpool);
            gettimeofday(&end, NULL);

            double elapsed = (end.tv_sec - start.tv_sec) * 1e6
                             (end.tv_usec - start.tv_usec);
            printf("Total time to verify: %lf us\n", elapsed);
            double throughput = (num_threads / elapsed) * 1e6; verifications/sec
            printf("Throughput: %lf verifications/sec\n\n", thrput);
            thpool_destroy(thpool);
        }

        free(m);
        free(sm);
        free(mout);
    }

    return 0;
}
