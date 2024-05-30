#ifndef SHELL_H_
#define SHELL_H_

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>

extern const struct shell *bacon_shell;

int init_shell();

#endif // SHELL_H_
