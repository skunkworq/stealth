package extract

// FieldKey is the canonical name of an extractable datum.
type FieldKey string

const (
	KeyLegalName FieldKey = "legal_name"
	KeyABN       FieldKey = "abn"
	KeyACN       FieldKey = "acn"
	KeyLicence   FieldKey = "licence"
	KeyPhone     FieldKey = "phone"
	KeyEmail     FieldKey = "email"
	KeyAddress   FieldKey = "address"
	KeyWebsite   FieldKey = "website"
	KeySocialFB  FieldKey = "social_facebook"
	KeySocialIG  FieldKey = "social_instagram"
	KeySocialLI  FieldKey = "social_linkedin"
	KeyLogoURL   FieldKey = "logo_url"
	KeyService   FieldKey = "service"
	KeyHours     FieldKey = "hours"
	KeyIndustry  FieldKey = "industry"
)

// FieldClass determines how the Validator normalises before the verbatim check.
type FieldClass int

const (
	ClassFreeText FieldClass = iota
	ClassIdentifier
	ClassEmail
	ClassURL
)

// ClassOf maps a key to its validation class.
func ClassOf(k FieldKey) FieldClass {
	switch k {
	case KeyABN, KeyACN, KeyLicence, KeyPhone:
		return ClassIdentifier
	case KeyEmail:
		return ClassEmail
	case KeyWebsite, KeySocialFB, KeySocialIG, KeySocialLI, KeyLogoURL:
		return ClassURL
	default:
		return ClassFreeText
	}
}

// Method records which extractor produced a value (for precedence + audit).
type Method string

const (
	MethodRegex          Method = "regex"
	MethodLdJSON         Method = "ld_json"
	MethodOgMeta         Method = "og_meta"
	MethodTelMailto      Method = "tel_mailto"
	MethodLLMLangextract Method = "llm_langextract"
)

// methodRank: higher wins single-valued merges. Deterministic > LLM.
func methodRank(m Method) int {
	switch m {
	case MethodLdJSON, MethodOgMeta, MethodTelMailto:
		return 3
	case MethodRegex:
		return 2
	case MethodLLMLangextract:
		return 1
	default:
		return 0
	}
}

// Span is a half-open [Start,End) range into SourceDocument.Text.
type Span struct{ Start, End int }

// Field is an emitted, verbatim-validated datum with provenance.
type Field struct {
	Key        FieldKey
	Class      FieldClass
	Value      string
	SourceRef  string
	Span       Span
	Method     Method
	Confidence float64
}

// Candidate is a proposed value before validation.
type Candidate struct {
	Key      FieldKey
	Value    string
	Method   Method
	Conf     float64
	SpanHint *Span
}
