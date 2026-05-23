/* cov-make-library doesn't find the standard include paths unless we specify a
 * compiler, so just define NULL here
 */
#ifndef NULL
#define NULL ((void *) 0)
#endif

// See comment in cov_nodefs.h for an explanation
void
g_clear_pointer(void **ptr, void (*destroy_fn)(void *))
{
    void *saved_ptr = NULL;

    if ((ptr == NULL) || (*ptr == NULL)) {
        return;
    }

    saved_ptr = *ptr;
    *ptr = NULL;
    destroy_fn(saved_ptr);
}
