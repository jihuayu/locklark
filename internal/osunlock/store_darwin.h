#ifndef LOCKLARK_OSUNLOCK_STORE_DARWIN_H
#define LOCKLARK_OSUNLOCK_STORE_DARWIN_H

// Maximum quick-unlock capsule size accepted by the native adapter. Keep in
// sync with the 8192-byte checks in store_darwin.go and passkey_darwin.h.
#define LL_UNLOCK_MAX 8192

// ll_unlock_store creates or replaces the scoped quick-unlock record. It uses
// the data protection keychain and a userPresence access control. The result
// is an OSStatus; 0 is success.
int ll_unlock_store(const char *id, const unsigned char *value, long n);

// ll_unlock_load reads the scoped record once with a fresh LAContext. On
// success *value points to a malloc'd copy owned by the caller (release with
// ll_unlock_clear_free) and *n is its length.
int ll_unlock_load(const char *id, unsigned char **value, long *n);

// ll_unlock_delete removes only the scoped record. A missing item is success.
int ll_unlock_delete(const char *id);

// ll_biometry_available returns 2 when Touch ID can evaluate the user-presence
// policy, 1 when only the device-owner (system password) policy is available,
// and 0 when neither is currently available. It never displays a prompt.
int ll_biometry_available(void);

// ll_unlock_clear_free zeroes the native buffer before freeing it.
void ll_unlock_clear_free(unsigned char *value, long n);

#endif
