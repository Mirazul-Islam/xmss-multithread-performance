#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"
#include "../thpool.h"

#define MAX_THREADS 16
#define XMSS_SIGNATURES 25

#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign

#define XMSS_VARIANT "XMSS-SHA2_10_256"

#define XMSS_MLEN_START 66891064
#define XMSS_INCREMENT_RATIO 2
#define XMSS_MLEN_LIMIT ((unsigned long long)1 * 1024 * 1024 * 1024) //1GB

struct sign_args {
    unsigned char *sk;
    unsigned char *sm;
    unsigned char *m;
    unsigned long long smlen;
    unsigned long long mlen;
};

void *sign_thread(void *arg)
{
    if (arg == NULL) {
        printf("Thread argument is NULL.\n");
        return NULL;
    }
    struct sign_args *sa = (struct sign_args *)arg;
    XMSS_SIGN(sa->sk, sa->sm, &(sa->smlen), sa->m, sa->mlen);
    return NULL;
}

int main()
{
    xmss_params params;
    uint32_t oid;

    if (XMSS_STR_TO_OID(&oid, XMSS_VARIANT)) {
        printf("XMSS variant %s not recognized!\n", XMSS_VARIANT);
        return -1;
    }
    XMSS_PARSE_OID(&params, oid);

    unsigned char **pk = malloc(sizeof(char *) * MAX_THREADS);
    unsigned char **sk = malloc(sizeof(char *) * MAX_THREADS);
    struct sign_args sa[MAX_THREADS];
    unsigned char *sm_arr[MAX_THREADS];
    unsigned char *m_arr[MAX_THREADS];

    for (int i = 0; i < MAX_THREADS; i++) {
        sk[i] = malloc(XMSS_OID_LEN + params.sk_bytes);
        if(!sk[i]) {
            printf("Memory allocation failed for sk.\n");
            free(pk);
            exit(1);
        }
        pk[i] = malloc(XMSS_OID_LEN + params.pk_bytes);

        if(!pk[i]) {
            printf("Memory allocation failed for pk.\n");
            exit(1);
        }

    }



    for (unsigned long long mlen = XMSS_MLEN_START; mlen <= XMSS_MLEN_LIMIT; mlen *= XMSS_INCREMENT_RATIO) {

        for (int num_threads = 1; num_threads <= MAX_THREADS; num_threads++) {
            threadpool thpool = thpool_init(num_threads);


            int sig_per_thread;
            for (int i = 0; i < num_threads; i++) {
                XMSS_KEYPAIR(pk[i], sk[i], oid);

                //Allocate memory for sm and m for each thread.
                sm_arr[i] = malloc(params.sig_bytes + mlen);
                m_arr[i] = malloc(mlen);
                randombytes(m_arr[i], mlen);

                sa[i].sk = sk[i];
                sa[i].sm = sm_arr[i];
                sa[i].m = m_arr[i];
                sa[i].smlen = 0;
                sa[i].mlen = mlen;


                if(num_threads <= 8)
                    sig_per_thread = num_threads * 8;
                else
                    sig_per_thread = num_threads * 4;

                for (int j = 0; j < sig_per_thread; j++) {
                    thpool_add_work(thpool, sign_thread, &sa[i]);
                }
            }

            double totalTime = 0;
            struct timeval t0, t1;
            gettimeofday(&t0, NULL);
            thpool_wait(thpool);
            gettimeofday(&t1, NULL);
            thpool_destroy(thpool);

            totalTime += (t1.tv_sec - t0.tv_sec) * 1000000.0;
            totalTime += t1.tv_usec - t0.tv_usec;
            totalTime /= 1000000.0;

            printf("mlen: %lluB, Thread(s): %d, Signatures per thread:"
                   " %d, Throughput: %f signatures/second.\n",
                   mlen, num_threads, sig_per_thread, (sig_per_thread) / totalTime);

            //Free allocated memory
            for (int i = 0; i < num_threads; i++) {
                free(m_arr[i]);
                free(sm_arr[i]);
            }
        }
    }

    //Free allocated memory
    for(int j = 0; j < MAX_THREADS; j++) {
        free(sk[j]);
        free(pk[j]);
    }
    free(sk);
    free(pk);

    return 0;
}