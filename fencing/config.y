%{
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <crm/crm.h>
#include <standalone_config.h>

extern int _line_count;
extern int yylex (void);
extern void yyset_in  (FILE * in_str  );
int yyerror(const char *foo);
static void handle_line_value(void);
static void reset_line(void);
static void add_line_value(char *key, char *val);

enum line_type {
	STANDALONE_LINE_DEVICE = 0,
	STANDALONE_LINE_OPTION,
	STANDALONE_LINE_PRIORITY,
	STANDALONE_LINE_PORT
};

static struct {
	enum line_type type;
	char *name;
	char *agent;
	char *keys[STANDALONE_CFG_MAX_KEYVALS];
	char *vals[STANDALONE_CFG_MAX_KEYVALS];
	int val_count;
	unsigned int priority;
} line_val = { 0, };

%}

%token <sval> T_VAL
%token T_DEVICE T_CONNECT T_PORTMAP T_PRIO
%token T_EQ T_ENDL T_UNFENCE T_OPTIONS
%left T_VAL

%start stuff

%union {
	char *sval;
	int ival;
}

%%

devline:
	T_DEVICE T_VAL T_VAL T_ENDL {
		line_val.name = $2;
		line_val.agent = $3;
		line_val.type = STANDALONE_LINE_DEVICE;
		handle_line_value();
	} |
	T_DEVICE T_VAL T_VAL assigns T_ENDL {
		line_val.name = $2;
		line_val.agent = $3;
		line_val.type = STANDALONE_LINE_DEVICE;
		handle_line_value();
	}
	;

optline:
	T_OPTIONS T_VAL assigns T_ENDL {
		line_val.name = $2;
		line_val.type = STANDALONE_LINE_OPTION;
		handle_line_value();
	}
	;

prioline:
	T_PRIO T_VAL T_VAL vals T_ENDL {
		int priority = crm_atoi($3, NULL);

		if (priority != -1) {
			line_val.name = $2;
			line_val.priority = priority;
			line_val.type = STANDALONE_LINE_PRIORITY;
			handle_line_value();
		} else {
			crm_err("Standalone Config parser error: priority value, %s, on line %d is not a valid positive integer\n", $3, _line_count);
			reset_line();
		}
	}
	;

portline:
	T_PORTMAP T_VAL portinfo T_ENDL {
		line_val.name = $2;
		line_val.type = STANDALONE_LINE_PORT;
		handle_line_value();
	}
	;

val:
	T_VAL {
		add_line_value(NULL, $1);
	}
	;

vals:
	vals val |
	val
	;

portinfo:
	assigns |
	vals
	;

assign:
	T_VAL T_EQ T_VAL {
		add_line_value($1, $3);
	}
	;

assigns:
	assigns assign |
	assign 
	;

stuff:
	T_ENDL stuff |
	//unfline stuff |
	devline stuff |
	portline stuff |
	optline stuff |
	prioline stuff |
	//unfline |
	portline |
	devline |
	optline |
	prioline |
	T_ENDL
	;

%%

int
yyerror(const char *foo)
{
	crm_err("Standalone Config parser error: %s on line %d\n", foo, _line_count);
	return 0;
}

static void
add_line_value(char *key, char *val)
{
	if (line_val.val_count < STANDALONE_CFG_MAX_KEYVALS) {
		line_val.keys[line_val.val_count] = key;
		line_val.vals[line_val.val_count] = val;
		line_val.val_count++;
	}
}

static void
reset_line()
{
	int i;
	crm_free(line_val.name);
	crm_free(line_val.agent);

	for (i = 0; i < line_val.val_count; i++) {
		crm_free(line_val.keys[i]);
		crm_free(line_val.vals[i]);
	}

	memset(&line_val, 0, sizeof(line_val));
}

static void
handle_line_value(void)
{
	int i;

	switch (line_val.type) {
	case STANDALONE_LINE_DEVICE:
		standalone_cfg_add_device(line_val.name, line_val.agent);
		/* fall through */
	case STANDALONE_LINE_OPTION:
		for (i = 0; i < line_val.val_count; i++) {
			standalone_cfg_add_device_options(line_val.name,
				line_val.keys[i],
				line_val.vals[i]);
		}
		break;
	case STANDALONE_LINE_PRIORITY:
		for (i = 0; i < line_val.val_count; i++) {
			standalone_cfg_add_node_priority(line_val.name,
				line_val.vals[i], /* fence device name */
				line_val.priority);
		}
		break;
	case STANDALONE_LINE_PORT:
		for (i = 0; i < line_val.val_count; i++) {
			if (line_val.keys[i]) {
				standalone_cfg_add_node(line_val.keys[i],
					line_val.name,
					line_val.vals[i]);
			} else {
				/* if value only, that means it is just a node name */
				standalone_cfg_add_node(line_val.vals[i],
					line_val.name,
					NULL);
			}
		}
		break;
	}
	reset_line();
}

int
standalone_cfg_read_file(const char *file_path)
{
	FILE *fp = fopen(file_path, "r");

	if (!fp) {
		return -1;
	}

	/* redirect parse input from stdin to our file */
	yyset_in(fp);
	yyparse();
	fclose(fp);

	return 0;
}

