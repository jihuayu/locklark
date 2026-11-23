#ifndef PASSME_OSUNLOCK_PASSKEY_DARWIN_H
#define PASSME_OSUNLOCK_PASSKEY_DARWIN_H

// Maximum capsule size accepted by the passkey verification read. Keep in sync
// with maxPasskeyCapsule in passkey.go.
#define PM_PASSKEY_MAX 8192

// pm_passkey_load reads the scoped quick-unlock capsule once with a fresh
// LAContext. On success *value points to a malloc'd copy owned by the caller
// (release with pm_passkey_clear_free) and *n is its length.
int pm_passkey_load(const char *id, unsigned char **value, long *n);

// pm_passkey_clear_free zeroes the native buffer before freeing it.
void pm_passkey_clear_free(unsigned char *value, long n);

#endif
