WRAPPED = calloc getenv getpwnam_r uname
WRAPPED_FLAGS = $(foreach fn,$(WRAPPED),-Wl,--wrap=$(fn))
