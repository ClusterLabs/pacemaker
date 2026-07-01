/* Coverity doesn't understand the g_clear_pointer() macro. We suppress the
 * macro expansion and provide a custom function model for g_clear_pointer().
 * Coverity support case 03702994 is open to request that Coverity ships a
 * model.
 */
#nodef g_clear_pointer
