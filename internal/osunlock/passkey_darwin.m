// Fresh per-operation keychain read used only by the passkey verification
// adapter in passkey_darwin.go. It lives in its own translation unit so the
// existing quick-unlock Store/Load/Delete code in store_darwin.go is unchanged.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include <stdlib.h>
#include <string.h>

#include "passkey_darwin.h"

#if __has_feature(objc_arc)
#define LL_CONTEXT_RETAIN(context) CFBridgingRetain(context)
#define LL_OBJC_RELEASE(object) ((void)(object))
#else
#define LL_CONTEXT_RETAIN(context) ((CFTypeRef)CFRetain((CFTypeRef)(context)))
#define LL_OBJC_RELEASE(object) [(object) release]
#endif

// Same scoped quick-unlock record as ll_query in store_darwin.go. This helper
// never creates, replaces or migrates the record.
static CFMutableDictionaryRef ll_passkey_query(const char *id) {
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
	CFRelease(account);
	return query;
}

int ll_passkey_load(const char *id, unsigned char **value, long *n) {
	if (!id || !value || !n) return -1;
	*value = NULL;
	*n = 0;
	// One fresh context per call: no successful evaluation from an earlier
	// unlock or passkey operation may release this capsule. A zero reuse
	// duration also forbids Touch ID reuse inside the same flow.
	LAContext *context = [[LAContext alloc] init];
	if (!context) return -1;
	context.touchIDAuthenticationAllowableReuseDuration = 0;
	// Explicit kSecUseAuthenticationContext: Security.framework runs the
	// item's userPresence evaluation (Touch ID or system password) itself.
	CFTypeRef contextRef = LL_CONTEXT_RETAIN(context);
	CFMutableDictionaryRef query = ll_passkey_query(id);
	CFTypeRef item = NULL;
	int status = -1;
	if (contextRef && query) {
		CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
		CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
		CFDictionarySetValue(query, kSecUseAuthenticationContext, contextRef);
		if (SecItemCopyMatching(query, &item) == errSecSuccess && item && CFGetTypeID(item) == CFDataGetTypeID()) {
			CFIndex length = CFDataGetLength((CFDataRef)item);
			if (length > 0 && length <= LL_PASSKEY_MAX) {
				unsigned char *copy = malloc((size_t)length);
				if (copy) {
					memcpy(copy, CFDataGetBytePtr((CFDataRef)item), (size_t)length);
					*value = copy;
					*n = (long)length;
					status = 0;
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

void ll_passkey_clear_free(unsigned char *value, long n) {
	if (!value) return;
	volatile unsigned char *p = value;
	while (n-- > 0) *p++ = 0;
	free(value);
}
