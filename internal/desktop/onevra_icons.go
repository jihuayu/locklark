package desktop

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"math"
	"os"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/passme/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

const (
	customIconMetaSectionID    = "_passme_meta"
	customIconMetaSectionTitle = "_meta"
	customIconMetaFieldID      = "_passme_icon"
	customIconMetaFieldLabel   = "icon"
	customIconMaxBytes         = 32768
	customIconIconPrefix       = "icon:"
	customIconPNGPrefix        = "img:image/png;base64,"
	customIconMaxImageFileSize = 8 << 20 // 8 MB
	customIconMaxBase64Bytes   = 24576   // 24 KB
)

type customIconColor struct {
	hex  string
	name string
}

var customIconPalette = []customIconColor{
	{hex: "#bd481b", name: "赤陶红"},
	{hex: "#1f7a68", name: "青绿色"},
	{hex: "#1d4ed8", name: "宝蓝色"},
	{hex: "#6d28d9", name: "紫罗兰"},
	{hex: "#be123c", name: "玫瑰红"},
	{hex: "#b45309", name: "琥珀橙"},
	{hex: "#047857", name: "翠绿色"},
	{hex: "#475569", name: "石板灰"},
}

type curatedIconEntry struct {
	key   string
	label string
	svg   func() *ui.SVG
}

var curatedItemIcons = []curatedIconEntry{
	{key: "key", label: "钥匙", svg: lucide.KeyRound},
	{key: "shield", label: "盾牌", svg: lucide.ShieldCheck},
	{key: "lock", label: "锁具", svg: lucide.Lock},
	{key: "fingerprint", label: "指纹", svg: lucide.FingerprintPattern},
	{key: "globe", label: "网站", svg: lucide.Globe},
	{key: "cloud", label: "云服务", svg: lucide.Cloud},
	{key: "server", label: "服务器", svg: lucide.Server},
	{key: "database", label: "数据库", svg: lucide.Database},
	{key: "terminal", label: "终端", svg: lucide.Terminal},
	{key: "code", label: "代码", svg: lucide.Code},
	{key: "git", label: "代码库", svg: lucide.GitBranch},
	{key: "wifi", label: "无线网络", svg: lucide.Wifi},
	{key: "mail", label: "邮箱", svg: lucide.Mail},
	{key: "user", label: "用户", svg: lucide.User},
	{key: "briefcase", label: "工作", svg: lucide.Briefcase},
	{key: "building", label: "企业", svg: lucide.Building},
	{key: "card", label: "银行卡", svg: lucide.CreditCard},
	{key: "bank", label: "银行", svg: lucide.Landmark},
	{key: "wallet", label: "钱包", svg: lucide.WalletCards},
	{key: "cart", label: "购物", svg: lucide.ShoppingBag},
	{key: "note", label: "笔记", svg: lucide.NotebookPen},
	{key: "file", label: "文档", svg: lucide.FileText},
	{key: "star", label: "收藏", svg: lucide.Star},
	{key: "smartphone", label: "手机", svg: lucide.Smartphone},
}

var curatedIconLookup = func() map[string]func() *ui.SVG {
	m := make(map[string]func() *ui.SVG, len(curatedItemIcons))
	for _, entry := range curatedItemIcons {
		m[entry.key] = entry.svg
	}
	return m
}()

// IsInternalMetaSection reports whether sec is the reserved Passme internal
// metadata section that must not be shown as user-editable custom fields.
func IsInternalMetaSection(sec vault.ItemSection) bool {
	return strings.EqualFold(sec.ID, customIconMetaSectionID)
}

// ExtractCustomIcon reads the item's custom icon specification from its
// reserved metadata section, returning "" if absent or oversized.
func ExtractCustomIcon(sections []vault.ItemSection) string {
	for _, sec := range sections {
		if !IsInternalMetaSection(sec) {
			continue
		}
		for _, f := range sec.Fields {
			if !strings.EqualFold(f.ID, customIconMetaFieldID) {
				continue
			}
			if f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP {
				continue
			}
			v := strings.TrimSpace(f.Value)
			if len(v) > customIconMaxBytes {
				return ""
			}
			return v
		}
	}
	return ""
}

// ApplyCustomIcon clones sections and inserts, updates, or removes the custom
// icon metadata field while dropping the metadata section if it becomes empty.
func ApplyCustomIcon(sections []vault.ItemSection, iconSpec string) []vault.ItemSection {
	spec := strings.TrimSpace(iconSpec)
	cloned := vault.CloneSections(sections)

	if spec == "" {
		if len(cloned) == 0 {
			return cloned
		}
		out := make([]vault.ItemSection, 0, len(cloned))
		for _, sec := range cloned {
			if !IsInternalMetaSection(sec) {
				out = append(out, sec)
				continue
			}
			kept := make([]vault.CustomField, 0, len(sec.Fields))
			for _, f := range sec.Fields {
				if !strings.EqualFold(f.ID, customIconMetaFieldID) {
					kept = append(kept, f)
				}
			}
			if len(kept) > 0 {
				sec.Fields = kept
				out = append(out, sec)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	iconField := vault.CustomField{
		ID:        customIconMetaFieldID,
		Label:     customIconMetaFieldLabel,
		Type:      vault.FieldTypeString,
		Value:     spec,
		Protected: false,
	}

	out := make([]vault.ItemSection, 0, len(cloned)+1)
	metaUpdated := false
	for _, sec := range cloned {
		if !IsInternalMetaSection(sec) {
			out = append(out, sec)
			continue
		}
		if metaUpdated {
			// Deduplicate any stray extra meta section carrying only the icon field.
			kept := make([]vault.CustomField, 0, len(sec.Fields))
			for _, f := range sec.Fields {
				if !strings.EqualFold(f.ID, customIconMetaFieldID) {
					kept = append(kept, f)
				}
			}
			if len(kept) > 0 {
				sec.Fields = kept
				out = append(out, sec)
			}
			continue
		}
		metaUpdated = true
		sec.ID = customIconMetaSectionID
		sec.Title = customIconMetaSectionTitle
		fieldUpdated := false
		for idx := range sec.Fields {
			if strings.EqualFold(sec.Fields[idx].ID, customIconMetaFieldID) {
				sec.Fields[idx] = iconField
				fieldUpdated = true
				break
			}
		}
		if !fieldUpdated {
			sec.Fields = append(sec.Fields, iconField)
		}
		out = append(out, sec)
	}
	if !metaUpdated {
		out = append(out, vault.ItemSection{
			ID:     customIconMetaSectionID,
			Title:  customIconMetaSectionTitle,
			Fields: []vault.CustomField{iconField},
		})
	}
	return out
}

func (a *App) onevraItemAvatar(c *ui.Context, title string, category vault.ItemCategory, customIcon string, size float32) {
	t := c.Theme()
	if strings.HasPrefix(customIcon, customIconPNGPrefix) {
		if bmp := a.cachedCustomIconBitmap(customIcon); bmp != nil {
			ui.Box(c).Size(size, size).Shrink(0).Radius(size * .28).Clip().Children(func() {
				ui.Image(c, bmp).Size(size, size).Fit(ui.Cover)
			})
			return
		}
		onevraAvatar(c, title, category, size)
		return
	}
	if key, hexColor, ok := parseCustomIconSpec(customIcon); ok {
		if svgFn, exists := curatedIconLookup[key]; exists {
			bg := t.Accent
			if hexColor != "" {
				if parsed, valid := parseHexColor(hexColor); valid {
					bg = parsed
				}
			}
			onevraAvatarBox(c, size, bg).Children(func() {
				oneui.Icon(c, svgFn()).Size(size*.52, size*.52).TextColor(ui.RGB(255, 255, 255))
			})
			return
		}
	}
	onevraAvatar(c, title, category, size)
}

func (a *App) onevraEditorAvatarPicker(c *ui.Context, title string, category vault.ItemCategory, customIcon *string, size float32) {
	t := c.Theme()
	current := ""
	if customIcon != nil {
		current = *customIcon
	}

	btn := ui.ButtonBase(c.Key("editor-avatar-picker")).Size(size, size).Shrink(0).Radius(size * .28).
		Cursor(ui.CursorPointer).Tooltip("修改图标（选择图标或上传图片）").Label("修改图标").Disabled(a.uiBusy(c))
	hovered := btn.Hovered() || btn.Focused()
	btn.Children(func() {
		a.onevraItemAvatar(c, title, category, current, size)
		if hovered && !a.busy {
			ui.Box(c).Absolute().Top(0).Left(0).Size(size, size).Radius(size * .28).
				Background(ui.RGBA(0, 0, 0, .28)).AlignItems(ui.Center).Justify(ui.Center).
				PassThrough().Children(func() {
				oneui.Icon(c, lucide.Pencil()).Size(size*.34, size*.34).TextColor(ui.RGB(255, 255, 255))
			})
		}
		badgeSize := float32(18)
		if size < 36 {
			badgeSize = 14
		}
		badgeBg := t.Surface
		badgeBorder := t.Border
		badgeFg := t.TextMuted
		if hovered {
			badgeBg = t.Accent
			badgeBorder = t.Accent
			badgeFg = t.AccentText
		}
		ui.Box(c).Absolute().Bottom(-2).Right(-2).Size(badgeSize, badgeSize).Radius(badgeSize/2).
			Background(badgeBg).Border(1, badgeBorder).AlignItems(ui.Center).Justify(ui.Center).
			PassThrough().Children(func() {
			oneui.Icon(c, lucide.Pencil()).Size(badgeSize*.56, badgeSize*.56).TextColor(badgeFg)
		})
	})
	if btn.Clicked() && !a.busy {
		a.openIconPicker(current)
	}
	a.onevraIconPickerDialog(c, title, category, customIcon)
}

func (a *App) defaultPickerTint() string {
	if a.settingsSnapshot().Accent == accentTeal {
		return "#1f7a68"
	}
	return "#bd481b"
}

func (a *App) openIconPicker(current string) {
	if _, hexColor, ok := parseCustomIconSpec(current); ok && hexColor != "" {
		a.onevra.iconPickerTint = hexColor
	} else if _, valid := parseHexColor(a.onevra.iconPickerTint); !valid {
		a.onevra.iconPickerTint = a.defaultPickerTint()
	}
	a.onevra.iconPickerOpen = true
}

func (a *App) resolvePickerTint(current string) string {
	if _, valid := parseHexColor(a.onevra.iconPickerTint); valid {
		return strings.ToLower(a.onevra.iconPickerTint)
	}
	if _, hexColor, ok := parseCustomIconSpec(current); ok && hexColor != "" {
		return hexColor
	}
	return a.defaultPickerTint()
}

func (a *App) onevraIconPickerDialog(c *ui.Context, title string, category vault.ItemCategory, customIcon *string) {
	t := c.Theme()
	ui.Column(c.Key("dialog-icon-picker")).Children(func() {
		oneui.Dialog(c, &a.onevra.iconPickerOpen, oneui.DialogOptions{Label: "修改条目图标"}, func(panel ui.Element) {
			panel.Width(460).Background(t.Surface).Border(1, t.Border).Radius(t.Radius * 1.5).Padding(t.Space(5))
			panel.Children(func() {
				current := ""
				if customIcon != nil {
					current = *customIcon
				}
				activeTint := a.resolvePickerTint(current)
				parsedKey, _, isIcon := parseCustomIconSpec(current)

				ui.Column(c).FillWidth().Gap(t.Space(3)).Children(func() {
					ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
						a.onevraItemAvatar(c, title, category, current, t.Space(10))
						ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
							oneui.Text(c, "修改条目图标").FontSize(t.Rem(1.15)).Bold()
							oneui.Text(c, "选择内置图标与底色，或上传本地图片").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
						})
					})

					ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						oneui.Text(c, "图标底色").FontSize(t.Rem(.78)).Bold().TextColor(t.TextMuted)
						ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
							for _, sw := range customIconPalette {
								sw := sw
								col, _ := parseHexColor(sw.hex)
								selected := strings.EqualFold(activeTint, sw.hex)
								btn := ui.ButtonBase(c.Key("icon-swatch-"+sw.hex)).Size(28, 28).Radius(14).
									Background(col).Cursor(ui.CursorPointer).Tooltip(sw.name).Label("选择底色 " + sw.name)
								if selected {
									btn.Border(2, t.Text)
								}
								btn.Children(func() {
									if selected {
										oneui.Icon(c, lucide.Check()).Size(14, 14).TextColor(ui.RGB(255, 255, 255))
									}
								})
								if btn.Clicked() && !a.busy {
									a.onevra.iconPickerTint = sw.hex
									if isIcon && customIcon != nil {
										*customIcon = formatIconSpec(parsedKey, sw.hex)
									}
								}
							}
						})
					})

					ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						oneui.Text(c, "内置图标").FontSize(t.Rem(.78)).Bold().TextColor(t.TextMuted)
						tintCol, ok := parseHexColor(activeTint)
						if !ok {
							tintCol = t.Accent
						}
						ui.Grid(c).Columns(6).FillWidth().Gap(t.Space(1.5)).Children(func() {
							for _, entry := range curatedItemIcons {
								entry := entry
								selected := isIcon && parsedKey == entry.key
								bg := t.Background
								borderCol := t.Border
								iconCol := t.Text
								if selected {
									bg = tintCol.Alpha(.14)
									borderCol = tintCol
									iconCol = tintCol
								}
								tile := ui.ButtonBase(c.Key("icon-tile-"+entry.key)).Height(44).FillWidth().
									Radius(t.Radius).Background(bg).Border(1, borderCol).
									Cursor(ui.CursorPointer).Tooltip(entry.label).Label("选择图标 " + entry.label)
								if tile.Hovered() && !selected {
									tile.Background(t.SurfaceHover)
								}
								tile.Children(func() {
									oneui.Icon(c, entry.svg()).Size(20, 20).TextColor(iconCol)
								})
								if tile.Clicked() && !a.busy && customIcon != nil {
									*customIcon = formatIconSpec(entry.key, activeTint)
								}
							}
						})
					})

					ui.Box(c).FillWidth().Height(1).Background(t.Border)

					ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "上传图片…", oneui.ButtonSecondary).Disabled(a.uiBusy(c)).Clicked() {
							a.pickAndEncodeCustomIconImage(customIcon)
						}
						if current != "" {
							if oneui.Button(c, "恢复默认", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() && customIcon != nil {
								*customIcon = ""
							}
						}
						ui.Spacer(c)
						if oneui.Button(c, "完成", oneui.ButtonPrimary).Clicked() {
							a.onevra.iconPickerOpen = false
						}
					})
				})
			})
		})
	})
}

func (a *App) cachedCustomIconBitmap(customIcon string) *ui.Bitmap {
	if len(customIcon) > customIconMaxBytes || !strings.HasPrefix(customIcon, customIconPNGPrefix) {
		return nil
	}
	if a.onevra.iconBitmaps == nil {
		a.onevra.iconBitmaps = make(map[string]*ui.Bitmap)
	}
	if bmp, cached := a.onevra.iconBitmaps[customIcon]; cached {
		return bmp
	}
	b64 := strings.TrimPrefix(customIcon, customIconPNGPrefix)
	if len(b64) == 0 {
		a.onevra.iconBitmaps[customIcon] = nil
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		a.onevra.iconBitmaps[customIcon] = nil
		return nil
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 512 || cfg.Height > 512 {
		a.onevra.iconBitmaps[customIcon] = nil
		return nil
	}
	bmp, err := ui.DecodeBitmap(raw)
	if err != nil || bmp == nil {
		a.onevra.iconBitmaps[customIcon] = nil
		return nil
	}
	a.onevra.iconBitmaps[customIcon] = bmp
	return bmp
}

func formatIconSpec(key, hexColor string) string {
	if hexColor != "" {
		return customIconIconPrefix + key + ":" + strings.ToLower(hexColor)
	}
	return customIconIconPrefix + key
}

func parseCustomIconSpec(spec string) (key, hexColor string, ok bool) {
	if !strings.HasPrefix(spec, customIconIconPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(spec, customIconIconPrefix)
	if rest == "" {
		return "", "", false
	}
	keyPart, colorPart, hasColon := strings.Cut(rest, ":")
	keyPart = strings.ToLower(strings.TrimSpace(keyPart))
	if keyPart == "" {
		return "", "", false
	}
	if _, exists := curatedIconLookup[keyPart]; !exists {
		return "", "", false
	}
	if hasColon {
		colorPart = strings.TrimSpace(colorPart)
		if _, valid := parseHexColor(colorPart); valid {
			return keyPart, strings.ToLower(colorPart), true
		}
		return keyPart, "", true
	}
	return keyPart, "", true
}

func parseHexColor(s string) (ui.Color, bool) {
	if !strings.HasPrefix(s, "#") {
		return ui.Color{}, false
	}
	hex := s[1:]
	switch len(hex) {
	case 3:
		r, ok1 := hexNibble(hex[0])
		g, ok2 := hexNibble(hex[1])
		b, ok3 := hexNibble(hex[2])
		if !ok1 || !ok2 || !ok3 {
			return ui.Color{}, false
		}
		return ui.RGB(r*17, g*17, b*17), true
	case 6:
		r, ok1 := hexByte(hex[0], hex[1])
		g, ok2 := hexByte(hex[2], hex[3])
		b, ok3 := hexByte(hex[4], hex[5])
		if !ok1 || !ok2 || !ok3 {
			return ui.Color{}, false
		}
		return ui.RGB(r, g, b), true
	default:
		return ui.Color{}, false
	}
}

func hexNibble(c byte) (uint8, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func hexByte(hi, lo byte) (uint8, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return (h << 4) | l, true
}

func (a *App) pickAndEncodeCustomIconImage(customIcon *string) {
	if customIcon == nil {
		return
	}
	win := a.win
	a.run(func() outcome {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: win,
			Title:  "选择条目图标图片",
			Filters: []mygo.FileFilter{
				{Name: "图片文件", Extensions: []string{"png", "jpg", "jpeg", "gif", "bmp"}},
			},
		})
		if err != nil {
			return outcome{err: err}
		}
		if len(paths) != 1 {
			return outcome{apply: func() {
				a.status = "已取消选择图片"
			}}
		}
		spec, msg, err := loadAndEncodeCustomIconFile(paths[0])
		if err != nil {
			return outcome{apply: func() {
				if msg != "" {
					a.status = msg
				} else {
					a.status = "无法加载所选图片"
				}
			}}
		}
		return outcome{apply: func() {
			*customIcon = spec
			a.status = "已更新条目自定义图片"
		}}
	})
}

var errCustomIconTooLarge = errors.New("custom icon exceeds size limit")

func loadAndEncodeCustomIconFile(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "无法读取所选图片文件", err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, customIconMaxImageFileSize+1))
	if err != nil {
		return "", "读取所选图片文件失败", err
	}
	if len(raw) == 0 {
		return "", "所选图片文件为空", errors.New("empty image file")
	}
	if len(raw) > customIconMaxImageFileSize {
		return "", "图片文件不能超过 8 MB", errCustomIconTooLarge
	}
	spec, err := encodeCustomIconBytes(raw)
	if err != nil {
		if errors.Is(err, errCustomIconTooLarge) {
			return "", "图片压缩后仍超出体积限制，请换一张图片", err
		}
		return "", "不支持该图片格式或图片已损坏（支持 PNG / JPEG / GIF / 24-32位 BMP）", err
	}
	return spec, "", nil
}

func encodeCustomIconBytes(raw []byte) (string, error) {
	img, err := decodeIconSourceImage(raw)
	if err != nil {
		return "", err
	}
	for _, size := range []int{64, 48} {
		square := resizeSquareRGBA(img, size)
		var buf bytes.Buffer
		enc := png.Encoder{CompressionLevel: png.BestCompression}
		if err := enc.Encode(&buf, square); err != nil {
			return "", err
		}
		b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
		if len(b64) <= customIconMaxBase64Bytes {
			return customIconPNGPrefix + b64, nil
		}
	}
	return "", errCustomIconTooLarge
}

func decodeIconSourceImage(raw []byte) (image.Image, error) {
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(raw)); err == nil {
		if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 8192 || cfg.Height > 8192 || int64(cfg.Width)*int64(cfg.Height) > 32_000_000 {
			return nil, errors.New("image dimensions out of bounds")
		}
		img, _, err := image.Decode(bytes.NewReader(raw))
		return img, err
	}
	if len(raw) >= 54 && raw[0] == 'B' && raw[1] == 'M' {
		return decodeUncompressedBMP(raw)
	}
	return nil, image.ErrFormat
}

// decodeUncompressedBMP decodes standard 24-bit and 32-bit BI_RGB BMP files
// so the Windows .bmp file filter works without extra dependencies.
func decodeUncompressedBMP(raw []byte) (image.Image, error) {
	if len(raw) < 54 || raw[0] != 'B' || raw[1] != 'M' {
		return nil, image.ErrFormat
	}
	pixelOffset := binary.LittleEndian.Uint32(raw[10:14])
	dibSize := binary.LittleEndian.Uint32(raw[14:18])
	if dibSize < 40 || pixelOffset < 14+dibSize {
		return nil, image.ErrFormat
	}
	width := int(int32(binary.LittleEndian.Uint32(raw[18:22])))
	heightSigned := int(int32(binary.LittleEndian.Uint32(raw[22:26])))
	topDown := heightSigned < 0
	height := heightSigned
	if topDown {
		height = -height
	}
	if width <= 0 || height <= 0 || width > 8192 || height > 8192 || int64(width)*int64(height) > 32_000_000 {
		return nil, image.ErrFormat
	}
	planes := binary.LittleEndian.Uint16(raw[26:28])
	bpp := binary.LittleEndian.Uint16(raw[28:30])
	compression := binary.LittleEndian.Uint32(raw[30:34])
	if planes != 1 || compression != 0 || (bpp != 24 && bpp != 32) {
		return nil, image.ErrFormat
	}
	rowStride := ((width*int(bpp) + 31) / 32) * 4
	needed := uint64(pixelOffset) + uint64(rowStride)*uint64(height)
	if needed > uint64(len(raw)) {
		return nil, image.ErrFormat
	}

	out := image.NewNRGBA(image.Rect(0, 0, width, height))
	bytesPerPx := int(bpp) / 8
	hasNonZeroAlpha := false
	for y := 0; y < height; y++ {
		srcY := height - 1 - y
		if topDown {
			srcY = y
		}
		rowOff := int(pixelOffset) + srcY*rowStride
		for x := 0; x < width; x++ {
			off := rowOff + x*bytesPerPx
			b, g, r := raw[off], raw[off+1], raw[off+2]
			a := uint8(255)
			if bytesPerPx == 4 {
				a = raw[off+3]
				if a != 0 {
					hasNonZeroAlpha = true
				}
			}
			out.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}
	if bytesPerPx == 4 && !hasNonZeroAlpha {
		for i := 3; i < len(out.Pix); i += 4 {
			out.Pix[i] = 255
		}
	}
	return out, nil
}

func resizeSquareRGBA(img image.Image, target int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, target, target))
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 || target <= 0 {
		return dst
	}
	side := min(w, h)
	cropX0 := b.Min.X + (w-side)/2
	cropY0 := b.Min.Y + (h-side)/2

	if side >= target {
		scale := float64(side) / float64(target)
		for dy := 0; dy < target; dy++ {
			fy0 := float64(dy) * scale
			fy1 := float64(dy+1) * scale
			iy0 := max(0, int(math.Floor(fy0)))
			iy1 := min(side-1, int(math.Ceil(fy1))-1)
			for dx := 0; dx < target; dx++ {
				fx0 := float64(dx) * scale
				fx1 := float64(dx+1) * scale
				ix0 := max(0, int(math.Floor(fx0)))
				ix1 := min(side-1, int(math.Ceil(fx1))-1)
				var sumR, sumG, sumB, sumA, sumW float64
				for iy := iy0; iy <= iy1; iy++ {
					wy := math.Min(fy1, float64(iy+1)) - math.Max(fy0, float64(iy))
					if wy <= 0 {
						continue
					}
					for ix := ix0; ix <= ix1; ix++ {
						wx := math.Min(fx1, float64(ix+1)) - math.Max(fx0, float64(ix))
						if wx <= 0 {
							continue
						}
						weight := wx * wy
						r, g, bl, a := img.At(cropX0+ix, cropY0+iy).RGBA()
						sumR += float64(r) * weight
						sumG += float64(g) * weight
						sumB += float64(bl) * weight
						sumA += float64(a) * weight
						sumW += weight
					}
				}
				if sumW <= 0 {
					continue
				}
				a8 := clampPremul8(sumA / sumW)
				dst.SetRGBA(dx, dy, color.RGBA{
					R: min(clampPremul8(sumR/sumW), a8),
					G: min(clampPremul8(sumG/sumW), a8),
					B: min(clampPremul8(sumB/sumW), a8),
					A: a8,
				})
			}
		}
		return dst
	}

	for dy := 0; dy < target; dy++ {
		sy := clampFloat((float64(dy)+0.5)*float64(side)/float64(target)-0.5, 0, float64(side-1))
		iy0 := int(math.Floor(sy))
		iy1 := min(side-1, iy0+1)
		wy := sy - float64(iy0)
		for dx := 0; dx < target; dx++ {
			sx := clampFloat((float64(dx)+0.5)*float64(side)/float64(target)-0.5, 0, float64(side-1))
			ix0 := int(math.Floor(sx))
			ix1 := min(side-1, ix0+1)
			wx := sx - float64(ix0)

			r00, g00, b00, a00 := img.At(cropX0+ix0, cropY0+iy0).RGBA()
			r10, g10, b10, a10 := img.At(cropX0+ix1, cropY0+iy0).RGBA()
			r01, g01, b01, a01 := img.At(cropX0+ix0, cropY0+iy1).RGBA()
			r11, g11, b11, a11 := img.At(cropX0+ix1, cropY0+iy1).RGBA()

			w00 := (1 - wx) * (1 - wy)
			w10 := wx * (1 - wy)
			w01 := (1 - wx) * wy
			w11 := wx * wy

			a8 := clampPremul8(float64(a00)*w00 + float64(a10)*w10 + float64(a01)*w01 + float64(a11)*w11)
			r8 := clampPremul8(float64(r00)*w00 + float64(r10)*w10 + float64(r01)*w01 + float64(r11)*w11)
			g8 := clampPremul8(float64(g00)*w00 + float64(g10)*w10 + float64(g01)*w01 + float64(g11)*w11)
			b8 := clampPremul8(float64(b00)*w00 + float64(b10)*w10 + float64(b01)*w01 + float64(b11)*w11)
			dst.SetRGBA(dx, dy, color.RGBA{
				R: min(r8, a8),
				G: min(g8, a8),
				B: min(b8, a8),
				A: a8,
			})
		}
	}
	return dst
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampPremul8(v16 float64) uint8 {
	v := int(math.Round(v16 / 257.0))
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
