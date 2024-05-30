#include <stdlib.h>
#include "shared_stuff.h"
#include "shell.h"

const struct shell *bacon_shell;

#ifdef CONFIG_SHELL_MODE

static int start_cmd(const struct shell *shell, size_t argc, char **argv)
{
	k_sem_give(&start);
	shell_print(bacon_shell, "Started isochronous transmission ...");
	return 0;
}

SHELL_CMD_REGISTER(start, NULL, "Start isocronous transmission", start_cmd);

#endif /* CONFIG_SHELL_MODE */

int init_shell()
{
	int err;

	bacon_shell = shell_backend_uart_get_ptr();
	err = shell_start(bacon_shell);
	shell_print(bacon_shell, "*** Welcome to the BACON OS ***");

	return err;
}
