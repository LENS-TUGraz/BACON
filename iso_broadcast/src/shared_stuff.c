#include "shared_stuff.h"

struct k_sem start;
uint16_t lamport_chain_len;

int init_shared_stuff()
{
	int err;
	err = k_sem_init(&start, 0, 1);
	return err;
}
