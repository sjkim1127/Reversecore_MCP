/*
 * PHP SPL Type Confusion — CVE-2022-31625
 * Vulnerable version: PHP 8.1.5
 *
 * Root cause: SplDoublyLinkedList::unserialize() does not validate that
 * the IT_MODE member is properly initialized before calling
 * spl_dllist_object_free_storage(), leading to an uninitialized pointer UAF.
 */
#include "php.h"
#include "spl_dllist.h"

static void spl_dllist_object_free_storage_vulnerable(zend_object *object) {
    spl_dllist_object *intern = spl_dllist_from_obj(object);
    /* VULNERABILITY: intern->llist may be NULL if unserialize partially ran */
    spl_ptr_llist_destroy(intern->llist); /* NULL ptr dereference / UAF */
    zend_object_std_dtor(&intern->std);
}
