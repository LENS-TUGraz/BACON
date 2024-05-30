#ifndef SHARED_STUFF_H_
#define SHARED_STUFF_H_

#include <zephyr/kernel.h>

extern struct k_sem start;

int init_shared_stuff();

#endif // SHARED_STUFF_H_