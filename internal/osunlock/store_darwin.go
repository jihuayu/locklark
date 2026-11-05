//go:build darwin && cgo

package osunlock

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static CFMutableDictionaryRef ll_query(const char *id) {
 CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 CFStringRef account=CFStringCreateWithCString(NULL,id,kCFStringEncodingUTF8);
 CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(q,kSecAttrService,CFSTR("app.locklark.unlock.v1"));
 CFDictionarySetValue(q,kSecAttrAccount,account); CFRelease(account);
 return q;
}
static int ll_store(const char *id, const unsigned char *value, long n) {
 CFErrorRef error=NULL;
 SecAccessControlRef acl=SecAccessControlCreateWithFlags(NULL,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,kSecAccessControlUserPresence,&error);
 if(error)CFRelease(error);
 if(!acl)return -1;
 CFMutableDictionaryRef q=ll_query(id);
 // Delete only this app's scoped record before replacement. Authentication is
 // enforced by Security.framework, never by a separate boolean prompt.
 OSStatus result=SecItemDelete(q);
 if(result!=errSecSuccess && result!=errSecItemNotFound){CFRelease(q);CFRelease(acl);return result;}
 CFDictionarySetValue(q,kSecAttrAccessControl,acl);
 CFDataRef data=CFDataCreate(NULL,value,n);
 CFDictionarySetValue(q,kSecValueData,data);
 result=SecItemAdd(q,NULL);
 CFRelease(data);CFRelease(acl);CFRelease(q);return result;
}
static int ll_load(const char *id,unsigned char **value,long *n) {
 CFMutableDictionaryRef q=ll_query(id);
 CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);
 CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
 CFDictionarySetValue(q,kSecUseOperationPrompt,CFSTR("Unlock Locklark"));
 CFTypeRef out=NULL;OSStatus result=SecItemCopyMatching(q,&out);CFRelease(q);
 if(result!=errSecSuccess)return result;
 if(!out || CFGetTypeID(out)!=CFDataGetTypeID()){if(out)CFRelease(out);return -1;}
 *n=CFDataGetLength((CFDataRef)out);
 if(*n<=0||*n>8192){CFRelease(out);return -1;}
 *value=malloc(*n);
 if(!*value){CFRelease(out);return -1;}
 memcpy(*value,CFDataGetBytePtr((CFDataRef)out),*n);CFRelease(out);return 0;
}
static void ll_clear_free(unsigned char *p,long n){if(p){volatile unsigned char *v=p;while(n-->0)*v++=0;free(p);}}
static int ll_delete(const char *id){CFMutableDictionaryRef q=ll_query(id);OSStatus r=SecItemDelete(q);CFRelease(q);return r==errSecItemNotFound?0:r;}
*/
import "C"
import "unsafe"

type keychain struct{}

func New() Store    { return keychain{} }
func Label() string { return "Touch ID / 系统密码" }
func Description() string {
	return "系统钥匙串要求用户验证（Touch ID 或系统密码），仅存于本设备。24 小时后需完整解锁。"
}
func (keychain) Store(id string, b []byte) error {
	if !validID(id) || len(b) == 0 || len(b) > 8192 {
		return ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	if C.ll_store(name, (*C.uchar)(unsafe.Pointer(&b[0])), C.long(len(b))) != 0 {
		return ErrUnavailable
	}
	return nil
}
func (keychain) Load(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	var value *C.uchar
	var n C.long
	if C.ll_load(name, &value, &n) != 0 {
		return nil, ErrUnavailable
	}
	defer C.ll_clear_free(value, n)
	return C.GoBytes(unsafe.Pointer(value), C.int(n)), nil
}
func (keychain) Delete(id string) error {
	if !validID(id) {
		return ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	if C.ll_delete(name) != 0 {
		return ErrUnavailable
	}
	return nil
}
