#ifndef LOCKLARK_OSUNLOCK_PASSKEY_DARWIN_H
#define LOCKLARK_OSUNLOCK_PASSKEY_DARWIN_H

// Maximum capsule size accepted by the passkey verification read. Keep in sync
// with maxPasskeyCapsule in passkey.go.
#define LL_PASSKEY_MAX 8192

// ll_passkey_load reads the scoped quick-unlock capsule once with a fresh
// LAContext. On success *value points to a malloc'd copy owned by the caller
// (release with ll_passkey_clear_free) and *n is its length.
int ll_passkey_load(const char *id, unsigned char **value, long *n);

// ll_passkey_clear_free zeroes the native buffer before freeing it.
void ll_passkey_clear_free(unsigned char *value, long n);

#endif
