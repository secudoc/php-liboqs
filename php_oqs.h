#ifndef PHP_OQS_H
#define PHP_OQS_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <php.h>
#include <oqs/oqs.h>

extern zend_module_entry oqs_module_entry;
#define phpext_oqs_ptr &oqs_module_entry

#define OQS_EXTENSION_NAME "oqs"
#define OQS_EXTENSION_VERSION "0.3.2"

#endif /* PHP_OQS_H */
