// Package terminalpeer observes one already-connected Darwin AF_UNIX peer
// process. It is an observational snapshot helper, not an authorization
// mechanism, an image-trust decision, or a lease credential.
//
// LOCAL_PEERTOKEN is the kernel's dynamic audit token for the socket's most
// recent accessor. It is not a connection-time snapshot: passing or inheriting
// a descriptor can change the accessor, and the token names the process the
// kernel resolves for the last accessor's PID at read time. This package
// therefore cannot prove which process generation originally called connect.
//
// A successful observation is bounded by two identical token and
// proc_pidpath_audittoken reads around one PROC_PIDTBSDINFO read. The token's
// pidversion selects the process generation for the token-bound path. The
// PROC_PIDTBSDINFO read supplies the PID, effective UID, start pair and
// controlling-terminal device. These reads are not atomic: a peer can exec,
// exit, change credentials, or change its controlling terminal between them.
// The double read can only reject changes it observes inside that window; it
// does not make the window atomic.
//
// The token-bound path is a pathname, not image contents, a signature, a file
// hash, or proof that the file still names the same executable. LOCAL_PEERUUID
// is not a process generation. A matching snapshot does not create, renew,
// reuse, or validate a lease, and it never widens one-shot, F17, T4, or other
// approval gates.
//
// The public API semantics were checked against Apple's published XNU sources.
// The running kernel is not that source tree, and this package does not claim
// that it is.
//
// This checkpoint does not test descriptor inheritance or descriptor passing;
// that accessor-change behavior is deferred to a later R1b checkpoint. PID
// reuse was not reproduced here. The tests cover real exec, real exit, and two
// distinct peers on distinct PTYs; no guarantee is claimed for a reused PID or
// for an accessor change caused by passing a descriptor.
package terminalpeer
