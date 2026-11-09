// Native macOS adapter for the quick-unlock capsule. It lives in its own
// translation unit because LAContext is Objective-C, while the Go package's
// other C helpers only need CoreFoundation.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include <stdlib.h>
#include <string.h>

#include "store_darwin.h"

#if __has_feature(objc_arc)
#define LL_CONTEXT_RETAIN(context) CFBridgingRetain(context)
#define LL_OBJC_RELEASE(object) ((void)(object))
#else
#define LL_CONTEXT_RETAIN(context) ((CFTypeRef)CFRetain((CFTypeRef)(context)))
#define LL_OBJC_RELEASE(object) [(object) release]
#endif

// One scoped quick-unlock record in the data protection keychain. The
// kSecUseDataProtectionKeychain flag is explicit: access-control items and
// keychain access groups are macOS data protection keychain features, not
// legacy login-keychain features.
static CFMutableDictionaryRef ll_unlock_query(const char *id) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!query) return NULL;
	CFStringRef account = CFStringCreateWithCString(NULL, id, kCFStringEncodingUTF8);
	if (!account) {
		CFRelease(query);
		return NULL;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, CFSTR("app.locklark.unlock.v1"));
	CFDictionarySetValue(query, kSecAttrAccount, account);
	CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFRelease(account);
	return query;
}

int ll_unlock_store(const char *id, const unsigned char *value, long n) {
	if (!id || !value || n <= 0 || n > LL_UNLOCK_MAX) return errSecParam;
	CFErrorRef error = NULL;
	SecAccessControlRef acl = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlUserPresence, &error);
	if (error) CFRelease(error);
	if (!acl) return errSecParam;
	CFDataRef data = CFDataCreate(NULL, value, (CFIndex)n);
	if (!data) {
		CFRelease(acl);
		return errSecAllocate;
	}
	CFMutableDictionaryRef query = ll_unlock_query(id);
	if (!query) {
		CFRelease(data);
		CFRelease(acl);
		return errSecParam;
	}
	CFMutableDictionaryRef changes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!changes) {
		CFRelease(query);
		CFRelease(data);
		CFRelease(acl);
		return errSecAllocate;
	}
	CFDictionarySetValue(changes, kSecValueData, data);
	CFDictionarySetValue(changes, kSecAttrAccessControl, acl);
	// Update first so a failed replacement leaves the previous enrollment
	// intact. SecItemUpdate cannot change the access control on every macOS
	// release; only that fixed errSecParam case falls back to deleting this
	// app's scoped record before adding the new one.
	OSStatus status = SecItemUpdate(query, changes);
	if (status == errSecItemNotFound) {
		CFMutableDictionaryRef add = CFDictionaryCreateMutableCopy(NULL, 0, query);
		if (!add) {
			status = errSecAllocate;
		} else {
			CFDictionarySetValue(add, kSecValueData, data);
			CFDictionarySetValue(add, kSecAttrAccessControl, acl);
			status = SecItemAdd(add, NULL);
			CFRelease(add);
		}
	} else if (status == errSecParam) {
		status = SecItemDelete(query);
		if (status == errSecSuccess || status == errSecItemNotFound) {
			CFMutableDictionaryRef add = CFDictionaryCreateMutableCopy(NULL, 0, query);
			if (!add) {
				status = errSecAllocate;
			} else {
				CFDictionarySetValue(add, kSecValueData, data);
				CFDictionarySetValue(add, kSecAttrAccessControl, acl);
				status = SecItemAdd(add, NULL);
				CFRelease(add);
			}
		}
	}
	CFRelease(changes);
	CFRelease(query);
	CFRelease(data);
	CFRelease(acl);
	return status;
}

int ll_unlock_load(const char *id, unsigned char **value, long *n) {
	if (!id || !value || !n) return errSecParam;
	*value = NULL;
	*n = 0;
	// One fresh context per call. The zero reuse duration forbids Touch ID
	// reuse from an earlier unlock, and the context is invalidated before it
	// is released so it can never authenticate another operation.
	LAContext *context = [[LAContext alloc] init];
	if (!context) return errSecInternalComponent;
	context.localizedReason = @"解锁 Locklark";
	context.touchIDAuthenticationAllowableReuseDuration = 0;
	CFTypeRef contextRef = LL_CONTEXT_RETAIN(context);
	CFMutableDictionaryRef query = ll_unlock_query(id);
	CFTypeRef item = NULL;
	OSStatus status = errSecParam;
	if (contextRef && query) {
		CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
		CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
		CFDictionarySetValue(query, kSecUseAuthenticationContext, contextRef);
		status = SecItemCopyMatching(query, &item);
		if (status == errSecSuccess) {
			if (!item || CFGetTypeID(item) != CFDataGetTypeID()) {
				status = errSecParam;
			} else {
				CFIndex length = CFDataGetLength((CFDataRef)item);
				if (length <= 0 || length > LL_UNLOCK_MAX) {
					status = errSecParam;
				} else {
					unsigned char *copy = malloc((size_t)length);
					if (!copy) {
						status = errSecAllocate;
					} else {
						memcpy(copy, CFDataGetBytePtr((CFDataRef)item), (size_t)length);
						*value = copy;
						*n = (long)length;
					}
				}
			}
		}
	}
	if (item) CFRelease(item);
	if (query) CFRelease(query);
	if (contextRef) CFRelease(contextRef);
	// Invalidate before release so this context can never authenticate again.
	[context invalidate];
	LL_OBJC_RELEASE(context);
	return status;
}

int ll_unlock_delete(const char *id) {
	if (!id) return errSecParam;
	CFMutableDictionaryRef query = ll_unlock_query(id);
	if (!query) return errSecParam;
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	if (status == errSecItemNotFound) return errSecSuccess;
	return status;
}

int ll_biometry_available(void) {
	// canEvaluatePolicy is a capability query, not an authentication request;
	// it neither prompts nor marks a context as authenticated. Each context is
	// invalidated and released immediately.
	LAContext *context = [[LAContext alloc] init];
	if (!context) return 0;
	NSError *error = nil;
	BOOL touchID = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
	[context invalidate];
	LL_OBJC_RELEASE(context);
	if (touchID) return 2;

	context = [[LAContext alloc] init];
	if (!context) return 0;
	error = nil;
	BOOL owner = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error];
	[context invalidate];
	LL_OBJC_RELEASE(context);
	return owner ? 1 : 0;
}

void ll_unlock_clear_free(unsigned char *value, long n) {
	if (!value) return;
	volatile unsigned char *p = value;
	while (n-- > 0) *p++ = 0;
	free(value);
}
