WRAPPED = calloc getenv uname
WRAPPED_FLAGS = $(foreach fn,$(WRAPPED),-Wl,--wrap=$(fn))
