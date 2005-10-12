#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#define SAME 1

int childflag = 0;
int grandchildflag = 0;
void *
grandchild_func(void * data)
{
        pid_t pid = (pid_t) data;

        if (pid ==  getpid()){
                grandchildflag = SAME;
        }

        if (grandchildflag ^ childflag){
                printf("Inconsistency detected\n");
        }
        return NULL;
}

void *
child_func(void * data)
{
        pid_t pid = (pid_t) data;
        pthread_t thread_id;

        if (pid ==  getpid()){
                childflag = SAME;
        }

        pthread_create(&thread_id, NULL, grandchild_func, (void*)getpid());

}

int
main()
{
        pthread_t thread_id;
        pthread_attr_t tattr;
        int  firsttime = 1;

        pthread_attr_init(&tattr);
        pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

again:
       if ( fork() == 0 ) { 
                childflag = 0; 
                grandchildflag =0;
                if (pthread_create(&thread_id, &tattr, child_func, (void*)getpid()) != 0){
                        printf("%s: creating thread failed", __FUNCTION__);
                }
                sleep(1);
                if (firsttime){
                        firsttime=0;
                        goto again;
                }
        }

        sleep(5);
        return 0;
}

