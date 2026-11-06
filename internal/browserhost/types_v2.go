package browserhost

// SupportedCapabilities is the fixed v2 negotiation list advertised by a
// shared desktop broker. Standalone native hosts keep their legacy shape and
// do not emit this list on "paired".
func SupportedCapabilities() []string {
	return []string{
		"shared-session-v1",
		"quick-fill-v1",
		"passkey-v1",
		"generate-v1",
		"stage-save-v1",
		"popup-vault-v1",
		"profile-fill-v1",
		"watchtower-v1",
		"cli-broker-v1",
	}
}

// BrowserPasswordProfile describes a generated password without exposing it.
type BrowserPasswordProfile struct {
	Mode             string `json:"mode"`
	Length           int    `json:"length"`
	AlphabetSize     int    `json:"alphabet_size"`
	EntropyBitsFloor int    `json:"entropy_bits_floor"`
}

type BrowserVaultSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}

type BrowserItemSummary struct {
	ID               string   `json:"id"`
	Revision         string   `json:"revision"`
	Category         string   `json:"category"`
	VaultID          string   `json:"vault_id"`
	Title            string   `json:"title"`
	Subtitle         string   `json:"subtitle,omitempty"`
	PrimaryURL       string   `json:"primary_url,omitempty"`
	State            string   `json:"state"`
	Favorite         bool     `json:"favorite,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	HasOTP           bool     `json:"has_otp,omitempty"`
	HasPasskey       bool     `json:"has_passkey,omitempty"`
	UpdatedAt        int64    `json:"updated_at,omitempty"`
	WatchtowerFlags  []string `json:"watchtower_flags,omitempty"`
	StrengthScore    int      `json:"strength_score,omitempty"`
	StrengthCategory string   `json:"strength_category,omitempty"`
}

type BrowserCustomField struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Concealed bool   `json:"concealed,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
}

type BrowserItemSection struct {
	ID     string               `json:"id"`
	Title  string               `json:"title"`
	Fields []BrowserCustomField `json:"fields,omitempty"`
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
	ID               string                    `json:"id"`
	Revision         string                    `json:"revision"`
	Category         string                    `json:"category"`
	VaultID          string                    `json:"vault_id"`
	Title            string                    `json:"title"`
	Username         string                    `json:"username,omitempty"`
	HasPassword      bool                      `json:"has_password,omitempty"`
	HasOTP           bool                      `json:"has_otp,omitempty"`
	HasNotes         bool                      `json:"has_notes,omitempty"`
	HasPasskey       bool                      `json:"has_passkey,omitempty"`
	URL              string                    `json:"url,omitempty"`
	URLs             []BrowserItemURL          `json:"urls,omitempty"`
	Favorite         bool                      `json:"favorite,omitempty"`
	AutoSubmit       *bool                     `json:"auto_submit,omitempty"`
	Tags             []string                  `json:"tags,omitempty"`
	State            string                    `json:"state"`
	Sections         []BrowserItemSection      `json:"sections,omitempty"`
	CreditCard       *BrowserCreditCardSummary `json:"credit_card,omitempty"`
	Identity         *BrowserIdentitySummary   `json:"identity,omitempty"`
	WatchtowerFlags  []string                  `json:"watchtower_flags,omitempty"`
	StrengthScore    int                       `json:"strength_score,omitempty"`
	StrengthCategory string                    `json:"strength_category,omitempty"`
	CreatedAt        int64                     `json:"created_at,omitempty"`
	UpdatedAt        int64                     `json:"updated_at,omitempty"`
}

type BrowserItemMutation struct {
	Category   string                  `json:"category"`
	VaultID    string                  `json:"vault_id,omitempty"`
	Title      string                  `json:"title"`
	Username   *string                 `json:"username,omitempty"`
	Password   *string                 `json:"password,omitempty"`
	OTP        *string                 `json:"otp,omitempty"`
	URL        *string                 `json:"url,omitempty"`
	URLs       []BrowserItemURL        `json:"urls,omitempty"`
	Notes      *string                 `json:"notes,omitempty"`
	Favorite   *bool                   `json:"favorite,omitempty"`
	AutoSubmit *bool                   `json:"auto_submit,omitempty"`
	Tags       []string                `json:"tags,omitempty"`
	Sections   []BrowserItemSection    `json:"sections,omitempty"`
	CreditCard *BrowserCreditCardInput `json:"credit_card,omitempty"`
	Identity   *BrowserIdentitySummary `json:"identity,omitempty"`
}

type BrowserStagedSave struct {
	StageID          string `json:"stage_id"`
	Origin           string `json:"origin"`
	Username         string `json:"username"`
	Title            string `json:"title"`
	Mode             string `json:"mode"`
	ExistingItemID   string `json:"existing_item_id,omitempty"`
	ExistingRevision string `json:"existing_revision,omitempty"`
	ExpiresAt        int64  `json:"expires_at"`
}

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
