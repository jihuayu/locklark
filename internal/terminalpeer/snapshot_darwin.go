//go:build darwin && cgo

package terminalpeer

/*
#cgo LDFLAGS: -lbsm

#include <errno.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>

struct ll_bsdinfo {
	unsigned int pid;
	unsigned int euid;
	unsigned long long start_sec;
	unsigned long long start_usec;
	unsigned int tty_dev;
};

static int
ll_peer_token(int fd, unsigned int *out, unsigned int *out_len)
{
	audit_token_t token;
	socklen_t len = sizeof(token);

	memset(&token, 0, sizeof(token));
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) {
		return errno != 0 ? errno : EIO;
	}
	*out_len = (unsigned int)len;
	memcpy(out, token.val, sizeof(token.val));
	return 0;
}

static void
ll_token_identity(const unsigned int *words, int *pid, int *pidversion,
    unsigned int *euid)
{
	audit_token_t token;

	memcpy(token.val, words, sizeof(token.val));
	*pid = audit_token_to_pid(token);
	*pidversion = audit_token_to_pidversion(token);
	*euid = (unsigned int)audit_token_to_euid(token);
}

static int
ll_token_path(const unsigned int *words, char *buf, unsigned int cap,
    unsigned int *out_len)
{
	audit_token_t token;
	int len;

	memcpy(token.val, words, sizeof(token.val));
	len = proc_pidpath_audittoken(&token, buf, cap);
	if (len <= 0) {
		return errno != 0 ? errno : ESRCH;
	}
	*out_len = (unsigned int)len;
	return 0;
}

static int
ll_pid_bsdinfo(int pid, struct ll_bsdinfo *out)
{
	struct proc_bsdinfo info;
	int len;

	memset(&info, 0, sizeof(info));
	memset(out, 0, sizeof(*out));
	len = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
	if (len != (int)sizeof(info)) {
		return errno != 0 ? errno : EIO;
	}
	out->pid = info.pbi_pid;
	// proc_pidbsdinfo fills pbi_uid from kauth_cred_getuid: effective UID.
	out->euid = (unsigned int)info.pbi_uid;
	out->start_sec = (unsigned long long)info.pbi_start_tvsec;
	out->start_usec = (unsigned long long)info.pbi_start_tvusec;
	out->tty_dev = info.e_tdev;
	return 0;
}
*/
import "C"

import (
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// socketIdentity reads the local socket object's device and inode with fstat.
// A duplicated descriptor keeps the identity; a different connection does not.
func socketIdentity(conn *net.UnixConn) (socketID, error) {
	if conn == nil {
		return socketID{}, ErrUnavailable
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return socketID{}, ErrUnavailable
	}
	var id socketID
	var statErr error
	if err := raw.Control(func(fd uintptr) {
		var st unix.Stat_t
		statErr = unix.Fstat(int(fd), &st)
		id = socketID{dev: uint64(uint32(st.Dev)), ino: uint64(st.Ino)}
	}); err != nil || statErr != nil || id.ino == 0 {
		return socketID{}, ErrUnavailable
	}
	return id, nil
}

// readPeerSample reads LOCAL_PEERTOKEN and then resolves the token-bound path.
// It preserves the token exactly; pid, pidversion and euid are accessors over
// that token, not fields parsed by this package.
func readPeerSample(conn *net.UnixConn) (peerSample, error) {
	if conn == nil {
		return peerSample{}, ErrUnavailable
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return peerSample{}, ErrUnavailable
	}
	var sample peerSample
	var callErr error
	if err := raw.Control(func(fd uintptr) {
		token, err := readPeerToken(int(fd))
		if err != nil {
			callErr = err
			return
		}
		pid, pidVersion, euid := tokenIdentity(token)
		if pid <= 0 || pidVersion <= 0 {
			callErr = ErrMalformed
			return
		}
		path, err := tokenPath(token)
		if err != nil {
			callErr = err
			return
		}
		sample = peerSample{
			token:      token,
			path:       path,
			pid:        pid,
			pidVersion: pidVersion,
			euid:       euid,
		}
	}); err != nil {
		return peerSample{}, ErrUnavailable
	}
	if callErr != nil {
		return peerSample{}, callErr
	}
	return sample, nil
}

// peerToken reads exactly one 32-byte audit_token_t. Any other length is
// unavailable; this package never pads or truncates a token into one.
func readPeerToken(fd int) (peerToken, error) {
	var token peerToken
	var length C.uint
	code := C.ll_peer_token(C.int(fd), (*C.uint)(unsafe.Pointer(&token[0])), &length)
	runtime.KeepAlive(token)
	if code != 0 {
		return peerToken{}, ErrUnavailable
	}
	if int(length) != tokenWords*4 {
		return peerToken{}, ErrUnavailable
	}
	return token, nil
}

// tokenIdentity uses the public audit-token accessors only.
func tokenIdentity(token peerToken) (pid int32, pidVersion int32, euid uint32) {
	var cpid C.int
	var cpidVersion C.int
	var ceuid C.uint
	C.ll_token_identity((*C.uint)(unsafe.Pointer(&token[0])), &cpid, &cpidVersion, &ceuid)
	runtime.KeepAlive(token)
	return int32(cpid), int32(cpidVersion), uint32(ceuid)
}

// tokenPath calls only proc_pidpath_audittoken, whose PIF_COMPARE_IDVERSION
// lookup binds the result to the token's pidversion. There is no path-only
// proc_pidpath(pid) fallback.
func tokenPath(token peerToken) (string, error) {
	buf := make([]byte, maxTokenPath)
	var length C.uint
	code := C.ll_token_path(
		(*C.uint)(unsafe.Pointer(&token[0])),
		(*C.char)(unsafe.Pointer(&buf[0])),
		C.uint(len(buf)),
		&length,
	)
	runtime.KeepAlive(token)
	if code != 0 {
		return "", ErrUnavailable
	}
	n := int(length)
	if n <= 0 || n >= len(buf) || buf[n] != 0 {
		return "", ErrMalformed
	}
	path := string(buf[:n])
	if !validTokenPath(path) {
		return "", ErrMalformed
	}
	return path, nil
}

// readPeerCredential reads PROC_PIDTBSDINFO for the token's PID. pbi_uid is
// the effective UID, and e_tdev is the controlling-terminal device.
func readPeerCredential(pid int32) (peerCredential, error) {
	if pid <= 0 {
		return peerCredential{}, ErrMalformed
	}
	var info C.struct_ll_bsdinfo
	if code := C.ll_pid_bsdinfo(C.int(pid), &info); code != 0 {
		return peerCredential{}, ErrUnavailable
	}
	cred := peerCredential{
		pid:       int32(info.pid),
		euid:      uint32(info.euid),
		startSec:  uint64(info.start_sec),
		startUsec: uint64(info.start_usec),
		ttyDev:    uint32(info.tty_dev),
	}
	if cred.pid != pid {
		return peerCredential{}, ErrMismatch
	}
	return cred, nil
}
