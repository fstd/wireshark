/* ct-main.c
 * ---------
 * Wiretap filter compilter
 */


#include <stdio.h>

#include "ct-compile.h"


int main(void)
{
	FILE	*yyin;

	yyin = stdin;

	compiler_init();
	wtap_parse();
	write_rt_lex();
	write_rt_yacc();

	return 0;
}
