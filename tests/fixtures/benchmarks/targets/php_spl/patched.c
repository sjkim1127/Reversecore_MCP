/*
 * PHP SPL Type Confusion Patched — CVE-2022-31625 fix
 *
 * Fix: Guard against NULL llist pointer before destruction.
 */
#include "php.h"
#include "spl_dllist.h"

static void spl_dllist_object_free_storage_patched(zend_object *object) {
    spl_dllist_object *intern = spl_dllist_from_obj(object);
    /* FIX: check for NULL before calling destroy */
    if (intern->llist) {
        spl_ptr_llist_destroy(intern->llist);
        intern->llist = NULL;
    }
    zend_object_std_dtor(&intern->std);
}
