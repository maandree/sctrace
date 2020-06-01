#include <pthread.h>
#include <unistd.h>

static int x;

static void *
thread_main(void *data)
{
	sleep(1);
	return data;
}

int
main(void)
{
	pthread_t thread;
	if (pthread_create(&thread, NULL, thread_main, &x))
		return 2;
	sleep(2);
	return 1;
}
