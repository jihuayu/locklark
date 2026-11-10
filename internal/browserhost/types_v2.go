package browserhost

// SupportedCapabilities is the fixed v2 negotiation baseline. Standalone native
// hosts advertise it on "paired"/"unlocked" authority grants exactly like a
// shared desktop broker does, so the baseline (attachments-v1 and the rest) is
// never accidentally revoked from manual pairing. The native clipboard lease is
// separate: Connection.pairedCapabilities appends it only when this host owns a
// real clipboard manager. Status answers keep the older shared-only shape.
func SupportedCapabilities() []string {
	return []string{
		"shared-session-v1",
		"quick-fill-v1",
		"passkey-v1",
		"passkey-management-v1",
		"passkey-conditional-v1",
		"passkey-signal-v1",
		"multiple-passkeys-v1",
		"generate-v1",
		"stage-save-v1",
		"popup-vault-v1",
		"profile-fill-v1",
		// Advertised only now that the native cross-origin checkout policy is
		// enforced in front of every card profile read.
		"checkout-frames-v1",
		"watchtower-v1",
		"attachments-v1",
		"history-v1",
		"cli-broker-v1",
	}
}

// BrowserPasskeyCandidate is the exact, metadata-only account list entry for a
// conditional ("passkey-list") request. It deliberately carries no private key,
// raw record, user handle or credential descriptor; the credential ID is the
// public selector the page already supplied in allowCredentials (if any).
type BrowserPasskeyCandidate struct {
	ItemID       string `json:"item_id"`
	Revision     string `json:"revision"`
	Title        string `json:"title"`
	CredentialID string `json:"credential_id"`
	// CredentialRevision is the opaque per-credential content revision. It is
	// the exact child selector a conditional selection must echo; it is not the
	// parent item revision and never enables a first-record fallback.
	CredentialRevision string `json:"credential_revision,omitempty"`
	RPID               string `json:"rp_id"`
	UserName           string `json:"user_name"`
	DisplayName        string `json:"display_name"`
}

// BrowserPasswordProfile describes a generated password without exposing it.
// It is the v2 name for the shared generated-profile DTO.
type BrowserPasswordProfile = GeneratedProfile

type BrowserVaultSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}

type BrowserItemSummary struct {
	ID         string   `json:"id"`
	Revision   string   `json:"revision"`
	Category   string   `json:"category"`
	VaultID    string   `json:"vault_id"`
	Title      string   `json:"title"`
	Subtitle   string   `json:"subtitle,omitempty"`
	PrimaryURL string   `json:"primary_url,omitempty"`
	State      string   `json:"state"`
	Favorite   bool     `json:"favorite,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	HasOTP     bool     `json:"has_otp,omitempty"`
	HasPasskey bool     `json:"has_passkey,omitempty"`
	// PasskeyCount is the number of durable credentials on this login. It is
	// the only per-credential signal in a list projection: arrays are bounded
	// to the detail frame so a 256-item list can never approach MaxOutput.
	PasskeyCount int `json:"passkey_count,omitempty"`
	// Passkey stays for old clients and only ever carries the unambiguous
	// single-credential projection.
	Passkey          *BrowserPasskey `json:"passkey,omitempty"`
	UpdatedAt        int64           `json:"updated_at,omitempty"`
	WatchtowerFlags  []string        `json:"watchtower_flags,omitempty"`
	StrengthScore    int             `json:"strength_score,omitempty"`
	StrengthCategory string          `json:"strength_category,omitempty"`
}

type BrowserCustomField struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Concealed bool   `json:"concealed,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	// HasValue reports that a durable value exists even when it is masked.
	HasValue bool `json:"has_value,omitempty"`
}

type BrowserItemSection struct {
	ID     string               `json:"id"`
	Title  string               `json:"title"`
	Fields []BrowserCustomField `json:"fields,omitempty"`
}

// BrowserAttachment is safe attachment metadata. The durable body is never part
// of a native response; bytes travel only through bounded attachment frames.
type BrowserAttachment struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	Size      int64  `json:"size"`
	MIMEType  string `json:"mime_type,omitempty"`
	SHA256    string `json:"sha256"`
	Protected bool   `json:"protected,omitempty"`
}

// BrowserItemMutationField is the mutation-only custom field input. Value is a
// pointer: an omitted value preserves the existing durable value stored under
// the stable field id, while an explicit value (even "") replaces it.
type BrowserItemMutationField struct {
	ID        string  `json:"id"`
	Label     string  `json:"label"`
	Type      string  `json:"type"`
	Value     *string `json:"value,omitempty"`
	Concealed bool    `json:"concealed,omitempty"`
	Purpose   string  `json:"purpose,omitempty"`
}

type BrowserItemMutationSection struct {
	ID     string                     `json:"id"`
	Title  string                     `json:"title"`
	Fields []BrowserItemMutationField `json:"fields,omitempty"`
}

type BrowserItemURL struct {
	Label     string `json:"label,omitempty"`
	URL       string `json:"url"`
	Primary   bool   `json:"primary,omitempty"`
	MatchMode string `json:"match_mode,omitempty"`
}

type BrowserCreditCardSummary struct {
	CardholderName string `json:"cardholder_name,omitempty"`
	Type           string `json:"type,omitempty"`
	Last4          string `json:"last4,omitempty"`
	MaskedNumber   string `json:"masked_number,omitempty"`
	ExpiryDate     string `json:"expiry_date,omitempty"`
	ValidFrom      string `json:"valid_from,omitempty"`
	IssuingBank    string `json:"issuing_bank,omitempty"`
	HasCVV         bool   `json:"has_cvv,omitempty"`
	HasPIN         bool   `json:"has_pin,omitempty"`
}

type BrowserCreditCardInput struct {
	CardholderName string  `json:"cardholder_name,omitempty"`
	Type           string  `json:"type,omitempty"`
	Number         *string `json:"number,omitempty"`
	Verification   *string `json:"verification,omitempty"`
	ExpiryDate     string  `json:"expiry_date,omitempty"`
	ValidFrom      string  `json:"valid_from,omitempty"`
	PIN            *string `json:"pin,omitempty"`
	IssuingBank    string  `json:"issuing_bank,omitempty"`
}

type BrowserIdentitySummary struct {
	Title        string `json:"title,omitempty"`
	FirstName    string `json:"first_name,omitempty"`
	MiddleName   string `json:"middle_name,omitempty"`
	LastName     string `json:"last_name,omitempty"`
	BirthDate    string `json:"birth_date,omitempty"`
	Company      string `json:"company,omitempty"`
	Department   string `json:"department,omitempty"`
	JobTitle     string `json:"job_title,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	AddressLine1 string `json:"address_line1,omitempty"`
	AddressLine2 string `json:"address_line2,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Website      string `json:"website,omitempty"`
}

type BrowserItemDetail struct {
	ID          string `json:"id"`
	Revision    string `json:"revision"`
	Category    string `json:"category"`
	VaultID     string `json:"vault_id"`
	Title       string `json:"title"`
	Username    string `json:"username,omitempty"`
	HasPassword bool   `json:"has_password,omitempty"`
	HasOTP      bool   `json:"has_otp,omitempty"`
	HasNotes    bool   `json:"has_notes,omitempty"`
	HasPasskey  bool   `json:"has_passkey,omitempty"`
	// Passkeys is the bounded per-credential metadata list. Passkey remains the
	// legacy single-credential field and is populated only when exactly one
	// credential exists.
	Passkeys         []BrowserPasskey          `json:"passkeys,omitempty"`
	Passkey          *BrowserPasskey           `json:"passkey,omitempty"`
	URL              string                    `json:"url,omitempty"`
	URLs             []BrowserItemURL          `json:"urls,omitempty"`
	Favorite         bool                      `json:"favorite,omitempty"`
	AutoSubmit       *bool                     `json:"auto_submit,omitempty"`
	Tags             []string                  `json:"tags,omitempty"`
	State            string                    `json:"state"`
	Sections         []BrowserItemSection      `json:"sections,omitempty"`
	Attachments      []BrowserAttachment       `json:"attachments,omitempty"`
	CreditCard       *BrowserCreditCardSummary `json:"credit_card,omitempty"`
	Identity         *BrowserIdentitySummary   `json:"identity,omitempty"`
	WatchtowerFlags  []string                  `json:"watchtower_flags,omitempty"`
	StrengthScore    int                       `json:"strength_score,omitempty"`
	StrengthCategory string                    `json:"strength_category,omitempty"`
	CreatedAt        int64                     `json:"created_at,omitempty"`
	UpdatedAt        int64                     `json:"updated_at,omitempty"`
}

// BrowserHistoryEntry is a metadata-only password-history row. The previous
// password and section snapshot never cross the browser boundary; the popup can
// list entries and ask the native host to restore one by index.
type BrowserHistoryEntry struct {
	Index       int    `json:"index"`
	Timestamp   int64  `json:"timestamp"`
	Action      string `json:"action,omitempty"`
	Title       string `json:"title,omitempty"`
	Username    string `json:"username,omitempty"`
	HasPassword bool   `json:"has_password"`
}

type BrowserItemMutation struct {
	Category   string                       `json:"category"`
	VaultID    string                       `json:"vault_id,omitempty"`
	Title      string                       `json:"title"`
	Username   *string                      `json:"username,omitempty"`
	Password   *string                      `json:"password,omitempty"`
	OTP        *string                      `json:"otp,omitempty"`
	URL        *string                      `json:"url,omitempty"`
	URLs       []BrowserItemURL             `json:"urls,omitempty"`
	Notes      *string                      `json:"notes,omitempty"`
	Favorite   *bool                        `json:"favorite,omitempty"`
	AutoSubmit *bool                        `json:"auto_submit,omitempty"`
	Tags       []string                     `json:"tags,omitempty"`
	Sections   []BrowserItemMutationSection `json:"sections,omitempty"`
	// ClearFields names the fields this mutation explicitly empties. Omitted
	// means "no explicit clear"; an empty list is the same as omitted.
	ClearFields []string                `json:"clear_fields,omitempty"`
	CreditCard  *BrowserCreditCardInput `json:"credit_card,omitempty"`
	Identity    *BrowserIdentitySummary `json:"identity,omitempty"`
}

// BrowserStagedSave is the v2 name for the shared staged-save DTO.
type BrowserStagedSave = StagedSave

type BrowserProfileSummary struct {
	ID        string `json:"id"`
	Revision  string `json:"revision"`
	Category  string `json:"category"`
	Title     string `json:"title"`
	Subtitle  string `json:"subtitle,omitempty"`
	CardBrand string `json:"card_brand,omitempty"`
	CardLast4 string `json:"card_last4,omitempty"`
	CardExp   string `json:"card_exp,omitempty"`
}

type BrowserCreditCardFill struct {
	CardholderName string `json:"cardholder_name"`
	Type           string `json:"type,omitempty"`
	Number         string `json:"number"`
	Verification   string `json:"verification,omitempty"`
	ExpiryDate     string `json:"expiry_date,omitempty"`
	ExpMonth       string `json:"exp_month,omitempty"`
	ExpYear        string `json:"exp_year,omitempty"`
	ExpYearShort   string `json:"exp_year_short,omitempty"`
	PIN            string `json:"pin,omitempty"`
}

type BrowserProfileFill struct {
	ItemID     string                  `json:"item_id"`
	Revision   string                  `json:"revision"`
	Category   string                  `json:"category"`
	Fields     map[string]string       `json:"fields"`
	Identity   *BrowserIdentitySummary `json:"identity,omitempty"`
	CreditCard *BrowserCreditCardFill  `json:"credit_card,omitempty"`
}

type BrowserWatchtowerCounts struct {
	Vulnerable    int `json:"vulnerable"`
	Reused        int `json:"reused"`
	Weak          int `json:"weak"`
	UnsecuredHTTP int `json:"unsecured_http"`
	TOTPNotStored int `json:"totp_not_stored"`
	Expiring      int `json:"expiring"`
}

type BrowserWatchtowerFinding struct {
	ID               string   `json:"id"`
	Revision         string   `json:"revision"`
	Title            string   `json:"title"`
	Origin           string   `json:"origin,omitempty"`
	Flags            []string `json:"flags"`
	StrengthScore    int      `json:"strength_score"`
	StrengthCategory string   `json:"strength_category"`
	ReuseCount       int      `json:"reuse_count,omitempty"`
	BreachCount      int      `json:"breach_count,omitempty"`
}

type BrowserWatchtowerSummary struct {
	Profile      string                     `json:"profile"`
	HIBPChecked  bool                       `json:"hibp_checked"`
	OverallScore int                        `json:"overall_score"`
	Checked      int                        `json:"checked"`
	Counts       BrowserWatchtowerCounts    `json:"counts"`
	SiteFindings []BrowserWatchtowerFinding `json:"site_findings"`
	Findings     []BrowserWatchtowerFinding `json:"findings"`
}

// BrokerCLIRequest and BrokerCLIResponse are stable aliases for desktop wiring.
type BrokerCLIRequest = CLIRunBrokerRequest
type BrokerCLIResponse = CLIRunBrokerResponse
