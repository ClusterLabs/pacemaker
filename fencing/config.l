%{
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "config.tab.h"

/* Some distributions can't use the output from flex without help */
#define ECHO if(fwrite( yytext, yyleng, 1, yyout ))

int _line_count = 1;

static void
_unescape(char *val)
{
	size_t x,y;
	int e = 0;

	y = strlen(val);
	for (x = 0; x < y; x++) {
		if (e == 1) {
			if (val[x] == '"') {
				memmove(&val[x-1], &val[x], y-x);
				--y;
				--x;
			}
			e = 0;
		}
		if (val[x] == '\\') {
			e = 1;
		}
	}
	val[y] = 0;
}

%}
%%
"\\\n" {
	++_line_count;
}

[\n] {
	++_line_count;
	return T_ENDL;
}

[ \t]* {}

\#[^\n]* {}

^"device" {
	return T_DEVICE;
}

^"options" {
	return T_OPTIONS;
}

^"priority" {
	return T_PRIO;
}

^"ports" {
	return T_PORTMAP;
}

^"unfence" {
	return T_UNFENCE;
}

"=" {
	return T_EQ;
}

[^ &\|!\t\(\){},;=\"\n\[\]]+ {
	yylval.sval = strdup(yytext);
	return T_VAL;
}

\"(\\\"|[^\"])+\" {
	yylval.sval = strdup(yytext+1);
	yylval.sval[strlen(yytext)-2] = 0;
	/* unescape backslash-quote to be quotes */
	_unescape(yylval.sval);
	return T_VAL;
}

\"\" {
	yylval.sval = NULL;
	return T_VAL;
}

%%
void
reset_vars(void)
{
	_line_count = 1;
}


int
yywrap(void)
{
	return 1;
}

int standalone_cfg_read_file(const char *file_path)
{
	FILE *fp = fopen(file_path, "r");

	if (!fp) {
		return -1;
	}
	yyin = fp;
	yyparse();

	fclose(fp);
	return 0;
}

