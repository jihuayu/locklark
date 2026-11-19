package vaultfile

// clonePolicySnapshot returns an independent deep copy of p, or nil when p is
// nil. A caller that keeps a policy as authenticated trusted state uses it so
// that no later change to the caller's proof bytes, or to the slice backing
// any policy field, can alter what that snapshot says.
//
// Every mutable reference reachable from p is copied: PrevPolicyDigest,
// OwnerRoot.PublicKey and OwnerRoot.Owners, Readers, Writers, Admins, Owners,
// AdminDelegations, Devices, every Device.ContentSigningKey.PublicKey, and
// every non-nil Device.PolicySigningKey together with its PublicKey bytes.
// Strings, scalars and value structs are copied by value. A nil slice stays
// nil and a non-nil slice is never shared with p; a nil key pointer stays nil.
// The snapshot shares no mutable storage with p in either direction.
func clonePolicySnapshot(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	q := *p
	q.PrevPolicyDigest = cloneBytes(p.PrevPolicyDigest)
	q.OwnerRoot.PublicKey = cloneBytes(p.OwnerRoot.PublicKey)
	q.OwnerRoot.Owners = cloneItems(p.OwnerRoot.Owners)
	q.Readers = cloneItems(p.Readers)
	q.Writers = cloneItems(p.Writers)
	q.Admins = cloneItems(p.Admins)
	q.Owners = cloneItems(p.Owners)
	q.AdminDelegations = cloneItems(p.AdminDelegations)
	q.Devices = cloneItems(p.Devices)
	for i := range q.Devices {
		q.Devices[i].ContentSigningKey.PublicKey = cloneBytes(p.Devices[i].ContentSigningKey.PublicKey)
		if k := p.Devices[i].PolicySigningKey; k != nil {
			kc := *k
			kc.PublicKey = cloneBytes(k.PublicKey)
			q.Devices[i].PolicySigningKey = &kc
		}
	}
	return &q
}

// cloneBytes returns a copy of b, preserving nil; len(b) == 0 allocates an
// empty slice, as bytes.Clone does.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// cloneItems returns a copy of s, preserving nil.
func cloneItems[S ~[]E, E any](s S) S {
	if s == nil {
		return nil
	}
	c := make(S, len(s))
	copy(c, s)
	return c
}
