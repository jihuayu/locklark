package vault

// ItemCategory enumerates the 1Password 8 parity item categories.
type ItemCategory string

const (
	CategoryLogin           ItemCategory = "login"
	CategoryPassword        ItemCategory = "password"
	CategorySecureNote      ItemCategory = "secure_note"
	CategoryCreditCard      ItemCategory = "credit_card"
	CategoryIdentity        ItemCategory = "identity"
	CategorySSHKey          ItemCategory = "ssh_key"
	CategoryAPICredential   ItemCategory = "api_credential"
	CategoryDatabase        ItemCategory = "database"
	CategoryServer          ItemCategory = "server"
	CategoryDocument        ItemCategory = "document"
	CategoryBankAccount     ItemCategory = "bank_account"
	CategoryWirelessRouter  ItemCategory = "wireless_router"
	CategorySoftwareLicense ItemCategory = "software_license"
	CategoryMembership      ItemCategory = "membership"
	CategoryCryptoWallet    ItemCategory = "crypto_wallet"
	CategoryMedicalRecord   ItemCategory = "medical_record"
)

// DefaultVaultID is the implicit personal vault that always exists.
const DefaultVaultID = "personal"

// ValidCategory reports whether c is one of the canonical item categories.
func ValidCategory(c ItemCategory) bool {
	switch c {
	case CategoryLogin, CategoryPassword, CategorySecureNote, CategoryCreditCard,
		CategoryIdentity, CategorySSHKey, CategoryAPICredential, CategoryDatabase,
		CategoryServer, CategoryDocument, CategoryBankAccount, CategoryWirelessRouter,
		CategorySoftwareLicense, CategoryMembership, CategoryCryptoWallet,
		CategoryMedicalRecord:
		return true
	default:
		return false
	}
}

// CategoryFromKind maps legacy v1 Kind strings ("login", "document", "ssh-key")
// and v2 category strings to canonical ItemCategory values.
func CategoryFromKind(kind string, cat ItemCategory) (ItemCategory, bool) {
	if cat != "" {
		if !ValidCategory(cat) {
			return "", false
		}
		if kind == "" || kind == string(cat) || (kind == "ssh-key" && cat == CategorySSHKey) {
			return cat, true
		}
		return "", false
	}
	switch kind {
	case "login":
		return CategoryLogin, true
	case "document":
		return CategoryDocument, true
	case "ssh-key", "ssh_key":
		return CategorySSHKey, true
	default:
		c := ItemCategory(kind)
		if ValidCategory(c) {
			return c, true
		}
		return "", false
	}
}
