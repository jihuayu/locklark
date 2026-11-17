package desktop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

// ItemDraft is the editable, unlocked representation of an item. It is
// created only from a reveal-authorized read and zeroed on cancel or lock.
type ItemDraft struct {
	ID       string
	Revision string
	Category vault.ItemCategory
	VaultID  string

	Title    string
	Username string
	Password string
	OTP      string
	URL      string
	Notes    string
	Favorite bool
	Icon     string
	Tags     []string

	URLs     []vault.ItemURL
	Sections []vault.ItemSection

	CreditCard vault.CreditCardDetails
	Identity   vault.IdentityDetails

	NewTag            string
	NewSectionTitle   string
	NewFieldLabel     string
	NewFieldType      vault.FieldType
	NewFieldValue     string
	NewFieldSection   int
	NewFieldProtected bool
	FieldDialogOpen   bool
	NewURL            string
	NewURLLabel       string
	NewURLMatch       string
	NewAttachment     string

	SSHKeyGenType string `json:"-"`
	SSHSeed       []byte `json:"-"`
	SSHPublicKey  []byte `json:"-"`
}

// field is a small template helper.
func field(id, label string, typ vault.FieldType, purpose string) vault.CustomField {
	f := vault.CustomField{ID: id, Label: label, Type: typ, Purpose: purpose}
	if typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP {
		f.Protected = true
	}
	return f
}

func section(id, title string, fields ...vault.CustomField) vault.ItemSection {
	return vault.ItemSection{ID: id, Title: title, Fields: fields}
}

// CategoryTemplate returns the default sections and fields provisioned for a
// new item of category. The returned slices are fresh and safe to mutate.
func CategoryTemplate(category vault.ItemCategory) []vault.ItemSection {
	switch category {
	case vault.CategoryCreditCard:
		return []vault.ItemSection{
			section("card", "卡片信息",
				field("cardholder", "持卡人姓名", vault.FieldTypeString, "cc-name"),
				field("type", "卡组织 / 类型", vault.FieldTypeMenu, "cc-type"),
				field("number", "卡号", vault.FieldTypeConcealed, "cc-number"),
				field("verification", "安全码 (CVV/CVC)", vault.FieldTypeConcealed, "cc-csc"),
				field("expiry", "有效期", vault.FieldTypeMonthYear, "cc-exp"),
				field("valid_from", "生效日期", vault.FieldTypeMonthYear, ""),
			),
			section("details", "发卡与限额",
				field("issuing_bank", "发卡银行", vault.FieldTypeString, ""),
				field("pin", "取现 / 交易 PIN", vault.FieldTypeConcealed, "cc-pin"),
				field("credit_limit", "信用额度", vault.FieldTypeString, ""),
			),
		}
	case vault.CategoryIdentity:
		return []vault.ItemSection{
			section("identification", "基本信息",
				field("last_name", "姓", vault.FieldTypeString, "family-name"),
				field("first_name", "名", vault.FieldTypeString, "given-name"),
				field("middle_name", "中间名", vault.FieldTypeString, "additional-name"),
				field("birth_date", "出生日期", vault.FieldTypeDate, "bday"),
				field("company", "公司 / 单位", vault.FieldTypeString, "organization"),
				field("department", "部门", vault.FieldTypeString, "department"),
				field("job_title", "职位", vault.FieldTypeString, "organization-title"),
			),
			section("documents", "证件信息",
				field("ssn", "身份证 / 证件号", vault.FieldTypeConcealed, "ssn"),
				field("passport_number", "护照号", vault.FieldTypeConcealed, "passport-number"),
				field("license_number", "驾驶证号", vault.FieldTypeConcealed, "license-number"),
			),
			section("contact", "联系方式与地址",
				field("email", "电子邮箱", vault.FieldTypeEmail, "email"),
				field("phone", "手机 / 电话", vault.FieldTypePhone, "tel"),
				field("country", "国家 / 地区", vault.FieldTypeString, "country"),
				field("state", "省 / 直辖市 / 州", vault.FieldTypeString, "address-level1"),
				field("city", "城市", vault.FieldTypeString, "address-level2"),
				field("address", "街道地址", vault.FieldTypeAddress, "street-address"),
				field("address_line2", "详细地址（楼栋/门牌）", vault.FieldTypeString, "address-line2"),
				field("postal_code", "邮政编码", vault.FieldTypeString, "postal-code"),
				field("website", "个人网站", vault.FieldTypeURL, ""),
			),
		}
	case vault.CategoryDocument:
		return nil
	case vault.CategorySSHKey:
		return []vault.ItemSection{
			section("ssh", "SSH 密钥信息",
				field("key_type", "密钥类型", vault.FieldTypeMenu, ""),
				field("public_key", "公钥", vault.FieldTypeText, ""),
				field("private_key", "私钥", vault.FieldTypeConcealed, ""),
				field("fingerprint", "指纹", vault.FieldTypeString, ""),
				field("passphrase", "私钥口令", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategoryAPICredential:
		return []vault.ItemSection{
			section("api", "API 凭据",
				field("type", "凭证类型", vault.FieldTypeMenu, ""),
				field("username", "用户名 / Access Key ID", vault.FieldTypeString, "username"),
				field("credential", "密钥 / Token", vault.FieldTypeConcealed, "password"),
				field("hostname", "服务端点 / URL", vault.FieldTypeURL, ""),
				field("valid_from", "生效日期", vault.FieldTypeDate, ""),
				field("expires", "过期日期", vault.FieldTypeDate, ""),
			),
		}
	case vault.CategoryDatabase:
		return []vault.ItemSection{
			section("database", "数据库连接",
				field("database_type", "数据库类型", vault.FieldTypeMenu, ""),
				field("server", "主机 / 地址", vault.FieldTypeString, ""),
				field("port", "端口", vault.FieldTypeString, ""),
				field("database", "数据库名", vault.FieldTypeString, ""),
				field("username", "用户名", vault.FieldTypeString, "username"),
				field("password", "密码", vault.FieldTypeConcealed, "password"),
				field("sid", "实例 / SID", vault.FieldTypeString, ""),
				field("options", "连接参数 / URI", vault.FieldTypeText, ""),
			),
		}
	case vault.CategoryServer:
		return []vault.ItemSection{
			section("server", "服务器访问",
				field("url", "服务器地址", vault.FieldTypeURL, ""),
				field("username", "用户名", vault.FieldTypeString, "username"),
				field("password", "密码", vault.FieldTypeConcealed, "password"),
			),
			section("admin_console", "管理控制台",
				field("admin_url", "控制台网址", vault.FieldTypeURL, ""),
				field("admin_username", "管理员账号", vault.FieldTypeString, ""),
				field("admin_password", "管理员密码", vault.FieldTypeConcealed, ""),
			),
			section("hosting", "托管服务商",
				field("name", "服务商名称", vault.FieldTypeString, ""),
				field("website", "服务商官网", vault.FieldTypeURL, ""),
				field("support_url", "技术支持网址", vault.FieldTypeURL, ""),
				field("support_phone", "客服电话", vault.FieldTypePhone, ""),
			),
		}
	case vault.CategoryWirelessRouter:
		return []vault.ItemSection{
			section("wifi", "无线网络 (Wi-Fi)",
				field("ssid", "网络名称 (SSID)", vault.FieldTypeString, ""),
				field("wireless_password", "Wi-Fi 密码", vault.FieldTypeConcealed, ""),
				field("security", "加密安全类型", vault.FieldTypeMenu, ""),
			),
			section("router", "路由器管理",
				field("name", "路由器 / 基站名称", vault.FieldTypeString, ""),
				field("server", "管理后台 IP / 地址", vault.FieldTypeString, ""),
				field("password", "管理后台密码", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategorySoftwareLicense:
		return []vault.ItemSection{
			section("license", "许可证",
				field("version", "软件版本", vault.FieldTypeString, ""),
				field("license_key", "激活码 / 序列号", vault.FieldTypeConcealed, ""),
				field("licensed_to", "授权对象", vault.FieldTypeString, ""),
				field("email", "注册邮箱", vault.FieldTypeEmail, ""),
				field("company", "所属公司", vault.FieldTypeString, ""),
				field("download_url", "下载地址", vault.FieldTypeURL, ""),
			),
			section("publisher", "发行商与订单",
				field("publisher", "发行商", vault.FieldTypeString, ""),
				field("publisher_website", "官方网站", vault.FieldTypeURL, ""),
				field("order_number", "订单号", vault.FieldTypeString, ""),
				field("purchase_date", "购买日期", vault.FieldTypeDate, ""),
				field("order_total", "订单金额", vault.FieldTypeString, ""),
			),
		}
	case vault.CategoryBankAccount:
		return []vault.ItemSection{
			section("bank", "银行账户",
				field("bank_name", "开户银行", vault.FieldTypeString, ""),
				field("owner", "开户人姓名", vault.FieldTypeString, ""),
				field("type", "账户类型", vault.FieldTypeMenu, ""),
				field("account_number", "银行账号 / 卡号", vault.FieldTypeConcealed, ""),
				field("telephone_pin", "电话 / 取款 PIN", vault.FieldTypeConcealed, ""),
				field("routing_number", "联行号 / Routing", vault.FieldTypeString, ""),
				field("swift", "SWIFT / BIC", vault.FieldTypeString, ""),
				field("iban", "IBAN", vault.FieldTypeString, ""),
			),
			section("branch", "支行信息",
				field("branch_address", "开户支行地址", vault.FieldTypeAddress, ""),
				field("branch_phone", "支行 / 客服电话", vault.FieldTypePhone, ""),
			),
		}
	case vault.CategoryCryptoWallet:
		return []vault.ItemSection{
			section("wallet", "加密钱包",
				field("wallet_type", "钱包类型", vault.FieldTypeMenu, ""),
				field("network", "主网 / 网络", vault.FieldTypeMenu, ""),
				field("address", "钱包地址", vault.FieldTypeString, ""),
				field("seed_phrase", "助记词 (Seed Phrase)", vault.FieldTypeConcealed, ""),
				field("private_key", "私钥", vault.FieldTypeConcealed, ""),
				field("password", "钱包密码", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategoryMedicalRecord:
		return []vault.ItemSection{
			section("medical", "医疗记录",
				field("patient_name", "姓名", vault.FieldTypeString, ""),
				field("blood_type", "血型", vault.FieldTypeMenu, ""),
				field("allergies", "过敏史", vault.FieldTypeText, ""),
				field("medications", "当前用药", vault.FieldTypeText, ""),
				field("conditions", "病史 / 诊断", vault.FieldTypeText, ""),
				field("doctor", "主治医生 / 医院", vault.FieldTypeString, ""),
				field("phone", "联系电话", vault.FieldTypePhone, ""),
				field("insurance_provider", "医保 / 保险机构", vault.FieldTypeString, ""),
				field("policy_number", "医保 / 保单号", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategoryMembership:
		return []vault.ItemSection{
			section("membership", "会员信息",
				field("organization", "机构 / 品牌", vault.FieldTypeString, ""),
				field("membership_number", "会员卡号 / ID", vault.FieldTypeConcealed, ""),
				field("pin", "PIN / 密码", vault.FieldTypeConcealed, ""),
				field("member_name", "会员姓名", vault.FieldTypeString, ""),
				field("member_since", "入会年月", vault.FieldTypeMonthYear, ""),
				field("expiry_date", "有效期至", vault.FieldTypeMonthYear, ""),
				field("website", "官方网站", vault.FieldTypeURL, ""),
				field("phone", "客服电话", vault.FieldTypePhone, ""),
			),
		}
	}
	// login, password and secure_note use the top-level username/password/
	// OTP/notes slots; their templates intentionally start with no custom
	// section so the primary fields are not duplicated.
	return nil
}

func newItemDraft(category vault.ItemCategory) *ItemDraft {
	if !vault.ValidCategory(category) {
		category = vault.CategoryLogin
	}
	vaultID := vault.DefaultVaultID
	return &ItemDraft{
		Category:      category,
		VaultID:       vaultID,
		NewFieldType:  vault.FieldTypeString,
		Sections:      CategoryTemplate(category),
		SSHKeyGenType: "Ed25519",
	}
}

func draftFromDetail(detail personal.ItemDetail) *ItemDraft {
	draft := &ItemDraft{
		ID:            detail.ID,
		Revision:      detail.Revision,
		Category:      detail.Category,
		VaultID:       detail.VaultID,
		Title:         detail.Title,
		Username:      detail.Username,
		Password:      detail.Password,
		OTP:           detail.OTP,
		URL:           detail.URL,
		Notes:         detail.Notes,
		Favorite:      detail.Favorite,
		Icon:          ExtractCustomIcon(detail.Sections),
		Tags:          append([]string(nil), detail.Tags...),
		URLs:          append([]vault.ItemURL(nil), detail.URLs...),
		Sections:      ApplyCustomIcon(detail.Sections, ""),
		NewFieldType:  vault.FieldTypeString,
		SSHKeyGenType: "Ed25519",
	}
	if detail.CreditCard != nil {
		draft.CreditCard = *detail.CreditCard
	}
	if detail.Identity != nil {
		draft.Identity = *detail.Identity
	}
	if draft.Category == "" {
		draft.Category = vault.CategoryLogin
	}
	if draft.VaultID == "" {
		draft.VaultID = vault.DefaultVaultID
	}
	// Legacy card/identity items may carry their values only in section
	// fields. The normalized view synthesizes the typed struct from section
	// purposes; use it for anything the detail did not provide directly.
	sectionsOnly := vault.Item{Category: draft.Category, Sections: draft.Sections}
	if detail.CreditCard == nil {
		if cc := sectionsOnly.NormalizedCreditCard(); cc != nil {
			draft.CreditCard = *cc
		}
	}
	if detail.Identity == nil {
		if identity := sectionsOnly.NormalizedIdentity(); identity != nil {
			draft.Identity = *identity
		}
	}
	// Fill typed members still empty from their canonical section fields, then
	// mirror the typed values back into the cloned template so the editor's
	// hidden duplicates cannot diverge before the first save.
	draft.canonicalFromSections()
	draft.syncCanonicalSections(draft.Sections)
	if draft.Category == vault.CategorySSHKey && detail.SSHPublicKey != "" {
		draft.populateSSHMetadata(detail.SSHPublicKey, detail.SSHFingerprint)
	}
	return draft
}

func (d *ItemDraft) item() vault.Item {
	kind := string(d.Category)
	switch d.Category {
	case vault.CategorySSHKey:
		kind = string(vault.CategorySSHKey)
	case vault.CategoryLogin:
		kind = "login"
	case vault.CategoryDocument:
		kind = "document"
	}
	item := vault.Item{
		ID:       d.ID,
		Kind:     kind,
		Category: d.Category,
		VaultID:  d.VaultID,
		Title:    strings.TrimSpace(d.Title),
		Username: d.Username,
		Password: d.Password,
		OTP:      d.OTP,
		URL:      strings.TrimSpace(d.URL),
		Notes:    d.Notes,
		Favorite: d.Favorite,
		Tags:     append([]string(nil), d.Tags...),
		URLs:     append([]vault.ItemURL(nil), d.URLs...),
		Sections: vault.CloneSections(d.Sections),
	}
	if d.Category == vault.CategorySSHKey {
		privPEM := sectionFieldValue(d.Sections, "ssh", "private_key")
		passphrase := sectionFieldValue(d.Sections, "ssh", "passphrase")
		seed, pubWire, hasEd := extractEd25519SSHMaterial(privPEM, passphrase)
		if !hasEd && strings.TrimSpace(privPEM) == "" && len(d.SSHSeed) == ed25519.SeedSize && len(d.SSHPublicKey) > 0 {
			seed = bytes.Clone(d.SSHSeed)
			pubWire = bytes.Clone(d.SSHPublicKey)
			hasEd = true
		}
		if hasEd {
			item.SSHSeed = seed
			item.SSHPublicKey = pubWire
			if item.Notes == "" && item.URL == "" && item.Username == "" && item.Password == "" && item.OTP == "" {
				item.Kind = "ssh-key"
			}
		}
	}
	if d.Category == vault.CategoryCreditCard {
		cc := d.CreditCard
		item.CreditCard = &cc
	}
	if d.Category == vault.CategoryIdentity {
		id := d.Identity
		item.Identity = &id
	}
	// The persisted default-section fields are duplicates of the typed
	// struct; normalization and autofill prefer the typed struct, so mirror the
	// typed values into the cloned sections to keep both representations equal.
	d.syncCanonicalSections(item.Sections)
	item.Sections = ApplyCustomIcon(item.Sections, d.Icon)
	return item
}

// v2CanonicalField binds one typed credit-card or identity draft member to
// the default template section/field that mirrors it. Editor inputs for these
// fields write the typed struct (which normalization and autofill prefer)
// instead of creating a second, divergent section value.
type v2CanonicalField struct {
	SectionID    string
	SectionTitle string
	FieldID      string
	Purpose      string
	Label        string
	Placeholder  string
	Concealed    bool
	value        func(*ItemDraft) *string
}

func (b v2CanonicalField) resolve(d *ItemDraft) *string {
	if d == nil || b.value == nil {
		return nil
	}
	return b.value(d)
}

// v2DraftCanonicalFields returns the typed bindings for a draft category.
func v2DraftCanonicalFields(category vault.ItemCategory) []v2CanonicalField {
	switch category {
	case vault.CategoryCreditCard:
		return []v2CanonicalField{
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "cardholder", Purpose: "cc-name", Label: "持卡人姓名", value: func(d *ItemDraft) *string { return &d.CreditCard.CardholderName }},
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "type", Purpose: "cc-type", Label: "卡组织 / 类型", value: func(d *ItemDraft) *string { return &d.CreditCard.Type }},
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "number", Purpose: "cc-number", Label: "卡号", Placeholder: "银行卡号", Concealed: true, value: func(d *ItemDraft) *string { return &d.CreditCard.Number }},
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "verification", Purpose: "cc-csc", Label: "安全码 (CVV/CVC)", Placeholder: "3–4 位安全码", Concealed: true, value: func(d *ItemDraft) *string { return &d.CreditCard.Verification }},
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "expiry", Purpose: "cc-exp", Label: "有效期", Placeholder: "YYYY-MM（例如 2029-08）", value: func(d *ItemDraft) *string { return &d.CreditCard.ExpiryDate }},
			{SectionID: "card", SectionTitle: "卡片信息", FieldID: "valid_from", Label: "生效日期", Placeholder: "YYYY-MM", value: func(d *ItemDraft) *string { return &d.CreditCard.ValidFrom }},
			{SectionID: "details", SectionTitle: "卡片信息", FieldID: "issuing_bank", Label: "发卡银行", value: func(d *ItemDraft) *string { return &d.CreditCard.IssuingBank }},
			{SectionID: "details", SectionTitle: "卡片信息", FieldID: "pin", Purpose: "cc-pin", Label: "取现 / 交易 PIN", Concealed: true, value: func(d *ItemDraft) *string { return &d.CreditCard.PIN }},
		}
	case vault.CategoryIdentity:
		return []v2CanonicalField{
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "last_name", Purpose: "family-name", Label: "姓", value: func(d *ItemDraft) *string { return &d.Identity.LastName }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "first_name", Purpose: "given-name", Label: "名", value: func(d *ItemDraft) *string { return &d.Identity.FirstName }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "middle_name", Purpose: "additional-name", Label: "中间名", value: func(d *ItemDraft) *string { return &d.Identity.MiddleName }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "birth_date", Purpose: "bday", Label: "出生日期", Placeholder: "YYYY-MM-DD", value: func(d *ItemDraft) *string { return &d.Identity.BirthDate }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "company", Purpose: "organization", Label: "公司 / 单位", value: func(d *ItemDraft) *string { return &d.Identity.Company }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "department", Purpose: "department", Label: "部门", value: func(d *ItemDraft) *string { return &d.Identity.Department }},
			{SectionID: "identification", SectionTitle: "基本信息", FieldID: "job_title", Purpose: "organization-title", Label: "职位", value: func(d *ItemDraft) *string { return &d.Identity.JobTitle }},
			{SectionID: "documents", SectionTitle: "证件信息", FieldID: "ssn", Purpose: "ssn", Label: "身份证 / 证件号", Concealed: true, value: func(d *ItemDraft) *string { return &d.Identity.SSN }},
			{SectionID: "documents", SectionTitle: "证件信息", FieldID: "passport_number", Purpose: "passport-number", Label: "护照号", Concealed: true, value: func(d *ItemDraft) *string { return &d.Identity.PassportNumber }},
			{SectionID: "documents", SectionTitle: "证件信息", FieldID: "license_number", Purpose: "license-number", Label: "驾驶证号", Concealed: true, value: func(d *ItemDraft) *string { return &d.Identity.LicenseNumber }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "email", Purpose: "email", Label: "电子邮箱", Placeholder: "name@example.com", value: func(d *ItemDraft) *string { return &d.Identity.Email }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "phone", Purpose: "tel", Label: "手机 / 电话", value: func(d *ItemDraft) *string { return &d.Identity.Phone }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "country", Purpose: "country", Label: "国家 / 地区", Placeholder: "例如：中国 / CN", value: func(d *ItemDraft) *string { return &d.Identity.Country }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "state", Purpose: "address-level1", Label: "省 / 直辖市 / 州", value: func(d *ItemDraft) *string { return &d.Identity.State }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "city", Purpose: "address-level2", Label: "城市", value: func(d *ItemDraft) *string { return &d.Identity.City }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "address", Purpose: "street-address", Label: "街道地址", value: func(d *ItemDraft) *string { return &d.Identity.AddressLine1 }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "address_line2", Purpose: "address-line2", Label: "详细地址（楼栋/门牌）", value: func(d *ItemDraft) *string { return &d.Identity.AddressLine2 }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "postal_code", Purpose: "postal-code", Label: "邮政编码", value: func(d *ItemDraft) *string { return &d.Identity.PostalCode }},
			{SectionID: "contact", SectionTitle: "联系方式与地址", FieldID: "website", Purpose: "url", Label: "个人网站", Placeholder: "https://example.com", value: func(d *ItemDraft) *string { return &d.Identity.Website }},
		}
	}
	return nil
}

// v2DraftCanonicalField reports whether a draft section field is the canonical
// duplicate of a typed member, matching by id first and then by purpose.
func v2DraftCanonicalField(d *ItemDraft, sectionID string, field vault.CustomField) (v2CanonicalField, bool) {
	if d == nil {
		return v2CanonicalField{}, false
	}
	bindings := v2DraftCanonicalFields(d.Category)
	for _, b := range bindings {
		if b.SectionID == sectionID && b.FieldID == field.ID {
			return b, true
		}
	}
	if sectionID == "contact" && field.ID == "address_line1" {
		for _, b := range bindings {
			if b.SectionID == "contact" && b.FieldID == "address" {
				return b, true
			}
		}
	}
	purpose := field.Purpose
	switch purpose {
	case "address-line1":
		purpose = "street-address"
	case "country-name":
		purpose = "country"
	case "cc-bank":
		for _, b := range bindings {
			if b.FieldID == "issuing_bank" {
				return b, true
			}
		}
	case "cc-valid-from":
		for _, b := range bindings {
			if b.FieldID == "valid_from" {
				return b, true
			}
		}
	}
	if purpose == "" {
		return v2CanonicalField{}, false
	}
	for _, b := range bindings {
		if b.SectionID == sectionID && b.Purpose == purpose {
			return b, true
		}
	}
	for _, b := range bindings {
		if b.Purpose == purpose {
			return b, true
		}
	}
	return v2CanonicalField{}, false
}

// v2DraftFieldValue returns the live draft member backing a canonical typed
// field, or nil when the field is an ordinary custom field whose value lives
// in Sections. Editor inputs bind directly to the returned pointer.
func v2DraftFieldValue(d *ItemDraft, sectionID, fieldID string) *string {
	if d == nil {
		return nil
	}
	if b, ok := v2DraftCanonicalField(d, sectionID, vault.CustomField{ID: fieldID}); ok {
		return b.resolve(d)
	}
	for i := range d.Sections {
		if d.Sections[i].ID != sectionID {
			continue
		}
		for j := range d.Sections[i].Fields {
			if d.Sections[i].Fields[j].ID == fieldID {
				return &d.Sections[i].Fields[j].Value
			}
		}
	}
	return nil
}

// v2CanonicalSectionValue reads the current template duplicate of a binding.
func v2CanonicalSectionValue(sections []vault.ItemSection, b v2CanonicalField) (string, bool) {
	for i := range sections {
		if sections[i].ID != b.SectionID {
			continue
		}
		for j := range sections[i].Fields {
			f := sections[i].Fields[j]
			if f.ID == b.FieldID || (b.Purpose != "" && f.Purpose == b.Purpose) {
				return f.Value, true
			}
		}
	}
	return "", false
}

// canonicalFromSections fills typed members that are still empty from their
// canonical section fields, so legacy section-only items are not blanked.
func (d *ItemDraft) canonicalFromSections() {
	for _, b := range v2DraftCanonicalFields(d.Category) {
		ptr := b.resolve(d)
		if ptr == nil || *ptr != "" {
			continue
		}
		if value, ok := v2CanonicalSectionValue(d.Sections, b); ok && value != "" {
			*ptr = value
		}
	}
}

// syncCanonicalSections mirrors the typed members into the given (cloned)
// section list. Fields that do not exist in the section are left absent; the
// typed struct alone then carries the value.
func (d *ItemDraft) syncCanonicalSections(sections []vault.ItemSection) {
	for _, b := range v2DraftCanonicalFields(d.Category) {
		ptr := b.resolve(d)
		if ptr == nil {
			continue
		}
		v2SetCanonicalSectionValue(sections, b, *ptr)
	}
}

func v2SetCanonicalSectionValue(sections []vault.ItemSection, b v2CanonicalField, value string) {
	for i := range sections {
		if sections[i].ID != b.SectionID {
			continue
		}
		for j := range sections[i].Fields {
			f := &sections[i].Fields[j]
			if f.ID == b.FieldID || (b.Purpose != "" && f.Purpose == b.Purpose) {
				f.Value = value
				if b.Concealed {
					f.Protected = true
				}
				return
			}
		}
	}
}

// normalizeFieldType maps the display names used by the editor to the
// canonical vault.FieldType set. "password", "credit-card-number" and
// "ssh-key" are aliases for a concealed field.
func normalizeFieldType(raw string) (vault.FieldType, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "string", "text":
		if strings.ToLower(strings.TrimSpace(raw)) == "text" {
			return vault.FieldTypeText, true
		}
		return vault.FieldTypeString, true
	case "concealed", "password", "credit-card-number", "credit_card_number", "ssh-key", "ssh_key":
		return vault.FieldTypeConcealed, true
	case "totp", "otp", "one-time password", "one_time_password":
		return vault.FieldTypeOTP, true
	case "url":
		return vault.FieldTypeURL, true
	case "email":
		return vault.FieldTypeEmail, true
	case "phone":
		return vault.FieldTypePhone, true
	case "date":
		return vault.FieldTypeDate, true
	case "month_year", "month-year", "monthyear":
		return vault.FieldTypeMonthYear, true
	case "address":
		return vault.FieldTypeAddress, true
	case "menu":
		return vault.FieldTypeMenu, true
	case "file":
		return vault.FieldTypeFile, true
	case "reference":
		return vault.FieldTypeReference, true
	}
	return "", false
}

func (a *App) newItem(category vault.ItemCategory) {
	if a.session == nil {
		return
	}
	a.EnableV2()
	if a.v2.nav == navWatchtower {
		a.v2.nav = navAllItems
	}
	if category == "" {
		category = a.v2.category
	}
	if category == "" {
		category = vault.CategoryLogin
	}
	if !vault.ValidCategory(category) {
		a.status = "未知条目类别：" + string(category)
		return
	}
	draft := newItemDraft(category)
	draft.VaultID = vault.DefaultVaultID
	if a.v2.vaultID != "" && a.v2.vaultID != "all" {
		draft.VaultID = a.v2.vaultID
	}
	a.v2.detail = nil
	a.v2.detailPlain = nil
	a.v2.selectedID, a.v2.selectedRevision = "", ""
	a.selected = nil
	a.v2.settingsOpen = false
	a.v2.generator.open = false
	a.v2.historyOpen = false
	a.v2.confirmPurge = false
	a.v2.draft = draft
	a.v2.editing = true
	a.v2.editorError = ""
	a.touchActivity()
	a.status = "新建条目：" + CategoryDisplayName(category)
}

func (a *App) NewItem(category vault.ItemCategory) {
	a.newItem(category)
}

// beginEdit reads the full unmasked item once, then stores only a draft.
// The read is audited by personal.GetItemDetail(revealConcealed=true).
func (a *App) beginEdit() error {
	if a.session == nil || a.v2.detail == nil {
		return personal.ErrMutationRefused
	}
	detail := *a.v2.detail
	if detail.State == "trashed" {
		a.status = "回收站中的条目需先恢复后才能编辑"
		return personal.ErrTrashed
	}
	s := a.session
	generation := a.generation
	a.run(func() outcome {
		plain, err := s.GetItemDetail(detail.ID, detail.Revision, true)
		if err != nil {
			return outcome{err: err}
		}
		return outcome{apply: func() {
			if a.generation != generation || a.session != s || a.v2.detail == nil || a.v2.detail.ID != detail.ID {
				return
			}
			a.v2.detailPlain = &plain
			a.v2.draft = draftFromDetail(plain)
			a.v2.editing = true
			a.v2.settingsOpen = false
			a.v2.generator.open = false
			a.v2.historyOpen = false
			a.v2.editorError = ""
			a.v2.revealed = map[string]bool{}
			a.touchActivity()
			a.status = "编辑条目：" + plain.Title
		}}
	})
	// The read is asynchronous; its failure is reported through a.status by the
	// dispatcher, never by a value read across goroutines here.
	return nil
}

func (a *App) EditSelected() error { return a.beginEdit() }
func (a *App) OpenEditor() error   { return a.beginEdit() }

// cancelEdit discards the draft and the plaintext detail beginEdit loaded.
// The draft already owns private copies of every value it shows, so nothing
// here may keep an unmasked detail without a reveal timer. Editor reveal state
// is cleared with it; an open Large Type view keeps the plaintext until it is
// closed, and releasePlainDetail drops it then. The generation bump makes any
// beginEdit read still in flight drop its result instead of repopulating an
// editor the user already left.
func (a *App) cancelEdit() {
	if !a.v2.editing {
		return
	}
	hadPartialEdit := a.v2.draft != nil && a.v2.draft.ID == ""
	a.generation++
	if a.v2.draft != nil {
		a.v2.draft.Password = ""
		a.v2.draft.OTP = ""
		a.v2.draft.CreditCard = vault.CreditCardDetails{}
		a.v2.draft.Identity = vault.IdentityDetails{}
		for i := range a.v2.draft.Sections {
			for j := range a.v2.draft.Sections[i].Fields {
				if a.v2.draft.Sections[i].Fields[j].Protected {
					a.v2.draft.Sections[i].Fields[j].Value = ""
				}
			}
		}
		clear(a.v2.draft.SSHSeed)
		clear(a.v2.draft.SSHPublicKey)
		a.v2.draft.SSHSeed = nil
		a.v2.draft.SSHPublicKey = nil
	}
	a.v2.draft = nil
	a.v2.editing = false
	a.v2.editorError = ""
	a.v2.revealed = map[string]bool{}
	a.v2.revealUntil = time.Time{}
	a.releasePlainDetail()
	// saveDraft derives its snapshot query from the current V2 filter. When a
	// guarded newer query is pending, the common query sequence moves with it
	// and the aborted save is ignored instead of failing.
	if hadPartialEdit && a.v2.pendingReload {
		a.v2.querySeq++
	}
	a.status = "已取消编辑；未保存"
}

func (a *App) CancelEdit() { a.cancelEdit() }

// saveDraft validates and persists the current editor draft. It preserves
// the sidebar filter/search and refreshes the same view after the mutation.
func (a *App) saveDraft() error {
	draft := a.v2.draft
	if draft == nil || a.session == nil {
		return personal.ErrMutationRefused
	}
	// Leave the editor exactly as cancelEdit does: the draft was the only
	// consumer of the beginEdit plaintext, and a successful save replaces it
	// with a masked read. The generation bump drops any in-flight beginEdit.
	a.generation++
	defer func() {
		a.v2.revealed = map[string]bool{}
		a.v2.revealUntil = time.Time{}
		a.releasePlainDetail()
	}()
	if strings.TrimSpace(draft.Title) == "" {
		a.v2.editorError = "标题不能为空"
		return personal.ErrMutationRefused
	}
	if !vault.ValidCategory(draft.Category) {
		a.v2.editorError = "未知条目类别"
		return personal.ErrMutationRefused
	}
	item := draft.item()
	s := a.session
	filter := a.currentFilter()
	isNew := draft.ID == ""
	var saved personal.ItemDetail
	var hasSaved bool
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		if isNew {
			id, revision, err := s.AddItem(item, g)
			if err != nil {
				return nativeResult{err: err}
			}
			item.ID = id
			saved, err = s.GetItemDetail(id, revision, false)
			if err != nil {
				return nativeResult{err: err}
			}
			hasSaved = true
		} else {
			revision, err := s.EditItem(draft.ID, draft.Revision, item, g)
			if err != nil {
				return nativeResult{err: err}
			}
			saved, err = s.GetItemDetail(draft.ID, revision, false)
			if err != nil {
				return nativeResult{err: err}
			}
			hasSaved = true
		}
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if a.v2.draft != nil {
			clear(a.v2.draft.SSHSeed)
			clear(a.v2.draft.SSHPublicKey)
		}
		a.v2.draft = nil
		a.v2.editing = false
		a.v2.editorError = ""
		a.applyV2Snapshot(snap, false)
		if hasSaved {
			a.v2.detail = &saved
			a.v2.selectedID, a.v2.selectedRevision = saved.ID, saved.Revision
			row := legacyRow(personal.ItemSummary{ID: saved.ID, Revision: saved.Revision, Kind: saved.Kind, Category: saved.Category, Title: saved.Title, State: saved.State, RestoreState: saved.RestoreState})
			a.selected = &row
		}
		a.status = "条目已保存"
	})
	if !ok {
		return personal.ErrMutationRefused
	}
	// The mutation is asynchronous; its failure is reported through a.status by
	// the dispatcher, never by a value read across goroutines here.
	return nil
}

func (a *App) SaveDraft() error { return a.saveDraft() }

// ---------- Custom sections and typed fields ----------

func nextSectionID(sections []vault.ItemSection) string {
	used := map[string]bool{}
	for _, s := range sections {
		used[strings.ToLower(s.ID)] = true
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("section-%d", n)
		if !used[id] {
			return id
		}
	}
}

func nextFieldID(section vault.ItemSection) string {
	used := map[string]bool{}
	for _, f := range section.Fields {
		used[strings.ToLower(f.ID)] = true
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("field-%d", n)
		if !used[id] {
			return id
		}
	}
}

func (a *App) addSection(title string) {
	if a.v2.draft == nil {
		return
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "新建分区"
	}
	a.v2.draft.Sections = append(a.v2.draft.Sections, vault.ItemSection{ID: nextSectionID(a.v2.draft.Sections), Title: title})
	a.v2.draft.NewSectionTitle = ""
	a.v2.editorError = ""
}

func (a *App) AddSection(title string) { a.addSection(title) }

func (a *App) removeSection(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections = append(a.v2.draft.Sections[:index], a.v2.draft.Sections[index+1:]...)
}

func (a *App) renameSection(index int, title string) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections[index].Title = strings.TrimSpace(title)
}

func (a *App) moveSection(index, delta int) {
	if a.v2.draft == nil {
		return
	}
	target := index + delta
	if index < 0 || index >= len(a.v2.draft.Sections) || target < 0 || target >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections[index], a.v2.draft.Sections[target] = a.v2.draft.Sections[target], a.v2.draft.Sections[index]
}

func (a *App) addField(sectionIndex int, label, typ, value string) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fieldType, ok := normalizeFieldType(typ)
	if !ok {
		a.v2.editorError = "未知字段类型：" + typ
		return
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "新字段"
	}
	f := vault.CustomField{ID: nextFieldID(a.v2.draft.Sections[sectionIndex]), Label: label, Type: fieldType, Value: value}
	if fieldType == vault.FieldTypeConcealed || fieldType == vault.FieldTypeOTP || fieldType == vault.FieldTypeTOTP {
		f.Protected = true
	}
	a.v2.draft.Sections[sectionIndex].Fields = append(a.v2.draft.Sections[sectionIndex].Fields, f)
	a.v2.draft.NewFieldLabel = ""
	a.v2.draft.NewFieldValue = ""
	a.v2.editorError = ""
}

func (a *App) AddField(sectionIndex int, label, typ, value string) {
	a.addField(sectionIndex, label, typ, value)
}

// SetFieldProtection switches a custom field between plaintext (明文) and encrypted (加密).
func (d *ItemDraft) SetFieldProtection(sectionIndex, fieldIndex int, encrypted bool) {
	if d == nil || sectionIndex < 0 || sectionIndex >= len(d.Sections) {
		return
	}
	fields := d.Sections[sectionIndex].Fields
	if fieldIndex < 0 || fieldIndex >= len(fields) {
		return
	}
	f := &d.Sections[sectionIndex].Fields[fieldIndex]
	f.Protected = encrypted
	if encrypted && f.Type == vault.FieldTypeString {
		f.Type = vault.FieldTypeConcealed
	} else if !encrypted && f.Type == vault.FieldTypeConcealed {
		f.Type = vault.FieldTypeString
	}
}

func (a *App) openAddCustomFieldDialog(sectionIndex int) {
	if a.v2.draft == nil {
		return
	}
	a.v2.draft.FieldDialogOpen = true
	a.v2.draft.NewFieldSection = sectionIndex
	a.v2.draft.NewFieldLabel = ""
	a.v2.draft.NewFieldValue = ""
	a.v2.draft.NewFieldType = vault.FieldTypeString
	a.v2.draft.NewFieldProtected = false
	a.v2.editorError = ""
}

func (a *App) confirmAddCustomField() {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	secIdx := draft.NewFieldSection
	if secIdx < 0 || secIdx >= len(draft.Sections) {
		a.addSection("自定义字段")
		secIdx = len(draft.Sections) - 1
	}
	if secIdx < 0 || secIdx >= len(draft.Sections) {
		return
	}
	label := strings.TrimSpace(draft.NewFieldLabel)
	if label == "" {
		label = "自定义字段"
	}
	typ := vault.FieldTypeString
	if draft.NewFieldProtected {
		typ = vault.FieldTypeConcealed
	} else if draft.NewFieldType != "" && draft.NewFieldType != vault.FieldTypeConcealed {
		typ = draft.NewFieldType
	}
	f := vault.CustomField{
		ID:        nextFieldID(draft.Sections[secIdx]),
		Label:     label,
		Type:      typ,
		Value:     draft.NewFieldValue,
		Protected: draft.NewFieldProtected,
	}
	draft.Sections[secIdx].Fields = append(draft.Sections[secIdx].Fields, f)
	draft.FieldDialogOpen = false
	draft.NewFieldLabel = ""
	draft.NewFieldValue = ""
	draft.NewFieldProtected = false
	a.v2.editorError = ""
}

func (a *App) removeField(sectionIndex, fieldIndex int) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	if fieldIndex < 0 || fieldIndex >= len(fields) {
		return
	}
	a.v2.draft.Sections[sectionIndex].Fields = append(fields[:fieldIndex], fields[fieldIndex+1:]...)
}

func (a *App) renameField(sectionIndex, fieldIndex int, label string) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	if fieldIndex < 0 || fieldIndex >= len(fields) {
		return
	}
	fields[fieldIndex].Label = strings.TrimSpace(label)
}

func (a *App) moveField(sectionIndex, fieldIndex, delta int) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	target := fieldIndex + delta
	if fieldIndex < 0 || fieldIndex >= len(fields) || target < 0 || target >= len(fields) {
		return
	}
	fields[fieldIndex], fields[target] = fields[target], fields[fieldIndex]
}

// reorderField moves a field from fromIndex to toIndex by splicing surrounding
// elements rather than only swapping adjacent items.
func (a *App) reorderField(sectionIndex, fromIndex, toIndex int) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	if fromIndex < 0 || fromIndex >= len(fields) || toIndex < 0 || toIndex >= len(fields) || fromIndex == toIndex {
		return
	}
	moved := fields[fromIndex]
	if fromIndex < toIndex {
		copy(fields[fromIndex:toIndex], fields[fromIndex+1:toIndex+1])
	} else {
		copy(fields[toIndex+1:fromIndex+1], fields[toIndex:fromIndex])
	}
	fields[toIndex] = moved
}

func sectionFieldValue(sections []vault.ItemSection, sectionID, fieldID string) string {
	for i := range sections {
		if sections[i].ID != sectionID {
			continue
		}
		for j := range sections[i].Fields {
			if sections[i].Fields[j].ID == fieldID {
				return sections[i].Fields[j].Value
			}
		}
	}
	return ""
}

func (d *ItemDraft) ensureSSHSection() int {
	if d == nil {
		return -1
	}
	for i := range d.Sections {
		if d.Sections[i].ID == "ssh" {
			return i
		}
	}
	tpl := CategoryTemplate(vault.CategorySSHKey)
	if len(tpl) == 0 {
		return -1
	}
	d.Sections = append([]vault.ItemSection{tpl[0]}, d.Sections...)
	return 0
}

func setSectionField(sec *vault.ItemSection, id, label string, typ vault.FieldType, protected bool, value string) {
	for i := range sec.Fields {
		if sec.Fields[i].ID == id {
			sec.Fields[i].Type = typ
			sec.Fields[i].Protected = protected
			sec.Fields[i].Value = value
			return
		}
	}
	sec.Fields = append(sec.Fields, vault.CustomField{
		ID:        id,
		Label:     label,
		Type:      typ,
		Protected: protected,
		Value:     value,
	})
}

func (d *ItemDraft) populateSSHMetadata(pubAuthorized, fingerprint string) {
	idx := d.ensureSSHSection()
	if idx < 0 {
		return
	}
	sec := &d.Sections[idx]
	if strings.TrimSpace(sectionFieldValue(d.Sections, "ssh", "key_type")) == "" {
		setSectionField(sec, "key_type", "密钥类型", vault.FieldTypeMenu, false, "Ed25519")
	}
	if strings.TrimSpace(sectionFieldValue(d.Sections, "ssh", "public_key")) == "" && pubAuthorized != "" {
		setSectionField(sec, "public_key", "公钥", vault.FieldTypeText, false, pubAuthorized)
	}
	if strings.TrimSpace(sectionFieldValue(d.Sections, "ssh", "fingerprint")) == "" && fingerprint != "" {
		setSectionField(sec, "fingerprint", "指纹", vault.FieldTypeString, false, fingerprint)
	}
}

func extractEd25519SSHMaterial(privPEM, passphrase string) ([]byte, []byte, bool) {
	if strings.TrimSpace(passphrase) != "" || !strings.Contains(privPEM, "BEGIN OPENSSH PRIVATE KEY") {
		return nil, nil, false
	}
	key, err := ssh.ParseRawPrivateKey([]byte(privPEM))
	if err != nil {
		return nil, nil, false
	}
	var priv ed25519.PrivateKey
	switch typed := key.(type) {
	case *ed25519.PrivateKey:
		if typed != nil {
			priv = *typed
			defer clear(*typed)
		}
	case ed25519.PrivateKey:
		priv = typed
		defer clear(typed)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, false
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, false
	}
	return bytes.Clone(priv[:ed25519.SeedSize]), pub.Marshal(), true
}

func generateSSHKeyMaterial(alg string) (keyType, pubAuthorized, privPEM, fingerprint string, seed, pubWire []byte, err error) {
	var rawPriv any
	var pubAny any
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "RSA-4096":
		keyType = "RSA-4096"
		priv, genErr := rsa.GenerateKey(rand.Reader, 4096)
		if genErr != nil {
			return "", "", "", "", nil, nil, genErr
		}
		defer func() {
			if priv.D != nil {
				priv.D.SetInt64(0)
			}
			for _, p := range priv.Primes {
				if p != nil {
					p.SetInt64(0)
				}
			}
		}()
		rawPriv = priv
		pubAny = &priv.PublicKey
	case "ECDSA":
		keyType = "ECDSA"
		priv, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return "", "", "", "", nil, nil, genErr
		}
		defer func() {
			if priv.D != nil {
				priv.D.SetInt64(0)
			}
		}()
		rawPriv = priv
		pubAny = &priv.PublicKey
	default:
		keyType = "Ed25519"
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return "", "", "", "", nil, nil, genErr
		}
		defer clear(priv)
		seed = bytes.Clone(priv.Seed())
		rawPriv = priv
		pubAny = pub
	}
	sshPub, err := ssh.NewPublicKey(pubAny)
	if err != nil {
		clear(seed)
		return "", "", "", "", nil, nil, err
	}
	pubAuthorized = strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	fingerprint = ssh.FingerprintSHA256(sshPub)
	if keyType == "Ed25519" {
		pubWire = sshPub.Marshal()
	}
	block, err := ssh.MarshalPrivateKey(rawPriv, "")
	if err != nil {
		clear(seed)
		clear(pubWire)
		return "", "", "", "", nil, nil, err
	}
	defer clear(block.Bytes)
	privPEM = string(pem.EncodeToMemory(block))
	return keyType, pubAuthorized, privPEM, fingerprint, seed, pubWire, nil
}

func (d *ItemDraft) applyGeneratedSSHKey(keyType, pubAuthorized, privPEM, fingerprint string, seed, pubWire []byte) {
	idx := d.ensureSSHSection()
	if idx < 0 {
		return
	}
	sec := &d.Sections[idx]
	setSectionField(sec, "key_type", "密钥类型", vault.FieldTypeMenu, false, keyType)
	setSectionField(sec, "public_key", "公钥", vault.FieldTypeText, false, pubAuthorized)
	setSectionField(sec, "private_key", "私钥", vault.FieldTypeConcealed, true, privPEM)
	setSectionField(sec, "fingerprint", "指纹", vault.FieldTypeString, false, fingerprint)
	setSectionField(sec, "passphrase", "私钥口令", vault.FieldTypeConcealed, true, "")
	clear(d.SSHSeed)
	clear(d.SSHPublicKey)
	d.SSHKeyGenType = keyType
	d.SSHSeed = bytes.Clone(seed)
	d.SSHPublicKey = bytes.Clone(pubWire)
}

func (a *App) generateDraftSSHKey(alg string) {
	draft := a.v2.draft
	if draft == nil || a.busy {
		return
	}
	if strings.TrimSpace(alg) == "" {
		alg = draft.SSHKeyGenType
	}
	if strings.TrimSpace(alg) == "" {
		alg = "Ed25519"
	}
	if strings.EqualFold(strings.TrimSpace(alg), "RSA-4096") && a.win != nil {
		targetDraft := draft
		a.run(func() outcome {
			kt, pubAuth, privPEM, fp, seed, pubWire, err := generateSSHKeyMaterial("RSA-4096")
			if err != nil {
				clear(seed)
				clear(pubWire)
				return outcome{err: personal.ErrSSHKey}
			}
			return outcome{
				drop: func() {
					clear(seed)
					clear(pubWire)
				},
				apply: func() {
					defer clear(seed)
					defer clear(pubWire)
					if a.v2.draft != targetDraft {
						return
					}
					targetDraft.applyGeneratedSSHKey(kt, pubAuth, privPEM, fp, seed, pubWire)
					a.status = "已生成 " + kt + " SSH 密钥对（" + fp + "）"
				},
			}
		})
		return
	}
	kt, pubAuth, privPEM, fp, seed, pubWire, err := generateSSHKeyMaterial(alg)
	defer clear(seed)
	defer clear(pubWire)
	if err != nil {
		a.status = message(personal.ErrSSHKey)
		return
	}
	draft.applyGeneratedSSHKey(kt, pubAuth, privPEM, fp, seed, pubWire)
	a.status = "已生成 " + kt + " SSH 密钥对（" + fp + "）"
}

// ---------- URLs, tags and favorites ----------

func (a *App) addURL(rawURL, label, matchMode string) {
	if a.v2.draft == nil {
		return
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		a.v2.editorError = "URL 不能为空"
		return
	}
	switch matchMode {
	case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
	default:
		a.v2.editorError = "未知的自动填充匹配模式"
		return
	}
	primary := len(a.v2.draft.URLs) == 0
	a.v2.draft.URLs = append(a.v2.draft.URLs, vault.ItemURL{Label: strings.TrimSpace(label), URL: rawURL, Primary: primary, MatchMode: matchMode})
	if a.v2.draft.URL == "" {
		a.v2.draft.URL = rawURL
	}
	a.v2.draft.NewURL = ""
	a.v2.draft.NewURLLabel = ""
	a.v2.editorError = ""
}

func (a *App) AddURL(rawURL, label, matchMode string) { a.addURL(rawURL, label, matchMode) }

func (a *App) removeURL(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	removedPrimary := a.v2.draft.URLs[index].Primary
	a.v2.draft.URLs = append(a.v2.draft.URLs[:index], a.v2.draft.URLs[index+1:]...)
	if removedPrimary && len(a.v2.draft.URLs) > 0 {
		a.v2.draft.URLs[0].Primary = true
	}
}

func (a *App) setPrimaryURL(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	for i := range a.v2.draft.URLs {
		a.v2.draft.URLs[i].Primary = i == index
	}
	a.v2.draft.URL = a.v2.draft.URLs[index].URL
}

func (a *App) setURLMatchMode(index int, mode string) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	switch mode {
	case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
		a.v2.draft.URLs[index].MatchMode = mode
	default:
		a.v2.editorError = "未知的自动填充匹配模式"
	}
}

func (a *App) addTag(tag string) {
	if a.v2.draft == nil {
		return
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return
	}
	for _, existing := range a.v2.draft.Tags {
		if strings.EqualFold(existing, tag) {
			return
		}
	}
	a.v2.draft.Tags = append(a.v2.draft.Tags, tag)
	a.v2.draft.NewTag = ""
}

func (a *App) AddTag(tag string) { a.addTag(tag) }

func (a *App) removeTag(tag string) {
	if a.v2.draft == nil {
		return
	}
	kept := a.v2.draft.Tags[:0]
	for _, existing := range a.v2.draft.Tags {
		if !strings.EqualFold(existing, tag) {
			kept = append(kept, existing)
		}
	}
	a.v2.draft.Tags = kept
}

func (a *App) toggleDraftFavorite() {
	if a.v2.draft != nil {
		a.v2.draft.Favorite = !a.v2.draft.Favorite
		return
	}
	a.toggleSelectedFavorite()
}

// toggleSelectedFavorite persists the star immediately, as the reference
// desktop does from both the list and detail view.
func (a *App) toggleSelectedFavorite() {
	if a.v2.detail == nil || a.session == nil {
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	favorite := !a.v2.detail.Favorite
	filter := a.currentFilter()
	var snap v2Snapshot
	var newRevision string
	a.runNative(func(g *personal.MutationGate) nativeResult {
		rev, err := s.SetFavorite(id, revision, favorite, g)
		if err != nil {
			return nativeResult{err: err}
		}
		newRevision = rev
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		if a.v2.detail != nil {
			a.v2.detail.Favorite = favorite
			a.v2.detail.Revision = newRevision
		}
		a.status = "已更新收藏"
	})
}

func (a *App) ToggleFavorite() { a.toggleSelectedFavorite() }

// saveSelectedTags persists tags immediately for the detail view.
func (a *App) saveSelectedTags(tags []string) {
	if a.v2.detail == nil || a.session == nil {
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	filter := a.currentFilter()
	var snap v2Snapshot
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if _, err := s.SetTags(id, revision, tags, g); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.v2.detail.Tags = append([]string(nil), tags...)
		a.status = "标签已更新"
	})
}

// fillGeneratorPassword writes the generated candidate into the draft
// password or the selected concealed field. The caller must save the draft;
// the old password is then recorded in item history by the store.
func (a *App) fillGeneratorPassword(value string) {
	if value == "" {
		return
	}
	if a.v2.draft == nil {
		return
	}
	target := a.v2.generator.target
	switch target {
	case "", "password":
		a.v2.draft.Password = value
	case "otp":
		a.v2.draft.OTP = value
	}
	if target != "" && target != "password" && target != "otp" {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) == 2 {
			for si := range a.v2.draft.Sections {
				if a.v2.draft.Sections[si].ID != parts[0] {
					continue
				}
				for fi := range a.v2.draft.Sections[si].Fields {
					if a.v2.draft.Sections[si].Fields[fi].ID == parts[1] {
						a.v2.draft.Sections[si].Fields[fi].Value = value
					}
				}
			}
		}
	}
	a.v2.generator.open = false
	a.status = "已填入生成的密码；保存条目后生效"
}

// CategoryDisplayName returns the localized Chinese label used by the sidebar,
// detail header, and item editor.
func CategoryDisplayName(category vault.ItemCategory) string {
	switch category {
	case vault.CategoryLogin:
		return "登录"
	case vault.CategoryPassword:
		return "密码"
	case vault.CategorySecureNote:
		return "安全笔记"
	case vault.CategoryCreditCard:
		return "信用卡"
	case vault.CategoryIdentity:
		return "身份信息"
	case vault.CategorySSHKey:
		return "SSH 密钥"
	case vault.CategoryAPICredential:
		return "API 凭据"
	case vault.CategoryDatabase:
		return "数据库"
	case vault.CategoryServer:
		return "服务器"
	case vault.CategoryWirelessRouter:
		return "无线路由器"
	case vault.CategorySoftwareLicense:
		return "软件许可"
	case vault.CategoryBankAccount:
		return "银行账户"
	case vault.CategoryCryptoWallet:
		return "加密钱包"
	case vault.CategoryMedicalRecord:
		return "医疗记录"
	case vault.CategoryDocument:
		return "文档"
	case vault.CategoryMembership:
		return "会员卡"
	}
	return string(category)
}

// AllCategories is the stable sidebar category order (16 categories: the 14
// benchmark categories plus password and membership).
func AllCategories() []vault.ItemCategory {
	return []vault.ItemCategory{
		vault.CategoryLogin,
		vault.CategoryPassword,
		vault.CategorySecureNote,
		vault.CategoryCreditCard,
		vault.CategoryIdentity,
		vault.CategorySSHKey,
		vault.CategoryAPICredential,
		vault.CategoryDatabase,
		vault.CategoryServer,
		vault.CategoryWirelessRouter,
		vault.CategorySoftwareLicense,
		vault.CategoryBankAccount,
		vault.CategoryCryptoWallet,
		vault.CategoryMedicalRecord,
		vault.CategoryDocument,
		vault.CategoryMembership,
	}
}

var _ = time.Now
