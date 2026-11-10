package onepux

import "github.com/jihuayu/locklark/internal/vault"

// releaseMappedItems wipes items the mapper still owns after a failure, then
// resets the result to an empty mapping. Ownership only transfers on a
// successful return, so these items never reach a caller.
func releaseMappedItems(out *MappedLogins) MappedLogins {
	for n := range out.Items {
		wipeItem(&out.Items[n])
	}
	// clear also zeroes the slots of the released backing store, so no stale
	// string or slice header survives behind the discarded result.
	clear(out.Items)
	out.Items = nil
	out.Report = MappingReport{}
	return MappedLogins{}
}

// wipeItem zeroes every string and byte-buffer an item may still hold.
func wipeItem(item *vault.Item) {
	clear(item.Attachment)
	for n := range item.Attachments {
		clear(item.Attachments[n].Content)
	}
	if item.CreditCard != nil {
		*item.CreditCard = vault.CreditCardDetails{}
	}
	if item.Identity != nil {
		*item.Identity = vault.IdentityDetails{}
	}
	clear(item.SSHSeed)
	clear(item.ImportSource)
	for n := range item.History {
		item.History[n].Password = ""
	}
	for n := range item.Sections {
		for m := range item.Sections[n].Fields {
			item.Sections[n].Fields[m].Value = ""
		}
	}
	item.ID, item.Kind, item.Title, item.Filename = "", "", "", ""
	item.Username, item.Password, item.OTP, item.Notes = "", "", "", ""
	item.URL, item.URLs, item.Tags = "", nil, nil
	*item = vault.Item{}
}

// releaseSourceFiles wipes and drops archive entry bytes buffered for
// attachment mapping. Only the mapper's own copies are touched; the caller's
// raw archive is never modified.
func releaseSourceFiles(files map[string][]byte) {
	for name, data := range files {
		clear(data)
		delete(files, name)
	}
}
