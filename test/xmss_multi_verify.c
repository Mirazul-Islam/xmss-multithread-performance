#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"
#include "../thpool.h"

#define XMSS_SIGNING_THREADS_START 1
#define XMSS_SIGNING_THREADS_LIMIT 16
#define NUM_TESTS 10

#ifdef XMSSMT
#define XMSS_PARSE_OID xmssmt_parse_oid
#define XMSS_STR_TO_OID xmssmt_str_to_oid
#define XMSS_KEYPAIR xmssmt_keypair
#define XMSS_SIGN xmssmt_sign
#else
#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#endif

#ifndef XMSS_VARIANT
#ifdef XMSSMT
#define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
#define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif
#endif

typedef struct {
    unsigned char *sk;
    unsigned char *sm;
    unsigned long long *smlen;
    unsigned char *m;
    unsigned long long mlen;
} sign_data;

void *sign_thread(void *arg)
{
    sign_data *data = (sign_data *) arg;
    XMSS_SIGN(data->sk, data->sm, data->smlen, data->m, data->mlen);
}

int main()
{
    unsigned long long mlen_values[] = {1024, 65536, 262144, 524288, 1048576, 67108864, 134217728, 268435456, 536870912, 1073741824};
    int mlen_values_count = sizeof(mlen_values)/sizeof(mlen_values[0]);

    for(int j = 0; j < mlen_values_count; j++)
    {
        unsigned long long mlen = mlen_values[j];

        xmss_params params;
        uint32_t oid;

        if (XMSS_STR_TO_OID(&oid, XMSS_VARIANT)) {
#ifdef XMSSMT
            printf("XMSSMT variant %s not recognized!\n", XMSS_VARIANT);
#else
            printf("XMSS variant %s not recognized!\n", XMSS_VARIANT);
#endif
            return -1;
        }

        XMSS_PARSE_OID(&params, oid);
        unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
        unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
        unsigned char *m = malloc(mlen);

        XMSS_KEYPAIR(pk, sk, oid);

        for (int num_threads = XMSS_SIGNING_THREADS_START; num_threads <= XMSS_SIGNING_THREADS_LIMIT; num_threads++)
        {
            double total_time = 0.0;
            printf("Current mlen: %llu, current number of threads: %d\n", mlen, num_threads);
            for(int test = 0; test < NUM_TESTS*num_threads; test++)
            {
                threadpool thpool = thpool_init(num_threads);

                struct timeval start, end;
                gettimeofday(&start, NULL);

                sign_data sign_args[num_threads];

                for(int i = 0; i < num_threads; i++)
                {
                    sign_data *this_arg = &sign_args[i];
                    this_arg->sk = sk;
                    this_arg->sm = malloc(params.sig_bytes + mlen);
                    this_arg->smlen = malloc(sizeof(unsigned long long));
                    this_arg->m = m;
                    this_arg->mlen = mlen;
                    thpool_add_work(thpool, sign_thread, (void *)this_arg);
                }

                thpool_wait(thpool);
                gettimeofday(&end, NULL);

                double elapsed = (end.tv_sec - start.tv_sec) * 1e6 +
                                 (end.tv_usec - start.tv_usec);

                total_time += elapsed;

                for(int i = 0; i < num_threads; i++)
                {
                    free(sign_args[i].sm);
                    free(sign_args[i].smlen);
                }

                thpool_destroy(thpool);
            }

            double average_time = total_time / num_threads * NUM_TESTS;
            printf("Average time for %d threads: %lf us\n", num_threads, average_time);
            double throughput = (num_threads * NUM_TESTS / total_time) * 1e6;  // signatures/sec
            printf("Average throughput: %lf signatures/sec\n\n", throughput);

        }

        free(m);
    }

    return 0;
}
