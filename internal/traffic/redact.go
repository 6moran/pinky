package traffic

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"
)

// Redaction, on by default (docs/notes/traffic-capture.md, "Safety"): the
// values of headers, query parameters and body fields whose names say
// they hold a credential are replaced with Redacted before an agent sees
// them, and so are bearer tokens and JWTs wherever they appear. Names and
// the shape of the request stay, which is what an agent working out an
// app's API needs.

// Redacted replaces a secret value.
const Redacted = "[redacted]"

// secretExact are names that are secrets only when they are the whole name
// (after lowercasing and dropping '-', '_' and '.'): "key" is, "keyword"
// is not.
var secretExact = map[string]bool{
	"key": true, "sig": true, "sid": true, "code": true, "otp": true, "pwd": true, "pass": true,
	"pin": true, "ticket": true, "auth": true, "csrf": true, "xsrf": true, "cvv": true, "cvc": true,
	"jwt": true, "nonce": true, "sign": true,
}

// secretParts are names that are secrets wherever they appear in the name.
var secretParts = []string{
	"token", "secret", "password", "passwd", "passcode", "session", "signature", "apikey",
	"authorization", "authentication", "cookie", "credential", "privatekey", "accesskey",
	"cardnumber", "securitycode", "verificationcode", "otpcode", "smscode", "authcode",
}

// SecretName reports whether a header, parameter or field name says its
// value is a credential: Authorization, Cookie, Set-Cookie, X-Api-Key,
// access_token, password, sessionId, sig and the like.
func SecretName(name string) bool {
	n := strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.', ' ':
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(name)))
	if n == "" {
		return false
	}
	if secretExact[n] {
		return true
	}
	// A leading "x" as in X-Auth or X-Sig.
	if strings.HasPrefix(n, "x") && secretExact[n[1:]] {
		return true
	}
	for _, p := range secretParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

var (
	// reBearer finds a bearer or basic credential in free text.
	reBearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// reJWT finds a JSON Web Token: three base64url parts, the first a
	// JSON header ("eyJ").
	reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
)

// RedactText replaces bearer credentials and JWTs in free text.
func RedactText(s string) string {
	s = reBearer.ReplaceAllStringFunc(s, func(m string) string {
		kind, _, _ := strings.Cut(m, " ")
		return kind + " " + Redacted
	})
	return reJWT.ReplaceAllString(s, Redacted)
}

// RedactHeaders returns the headers with secret values replaced.
func RedactHeaders(hs []Header) []Header {
	out := make([]Header, len(hs))
	for i, h := range hs {
		v := h.Value
		if SecretName(h.Name) {
			v = Redacted
		} else {
			v = RedactText(v)
		}
		out[i] = Header{Name: h.Name, Value: v}
	}
	return out
}

// RedactURL replaces the values of secret query parameters, a password in
// the URL's user info, and tokens anywhere in it. A URL that does not
// parse is redacted as text.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return RedactText(raw)
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), Redacted)
		}
	}
	if u.RawQuery != "" {
		u.RawQuery = redactQuery(u.RawQuery)
	}
	// url.String escapes the brackets of Redacted in user info.
	s := strings.ReplaceAll(u.String(), url.QueryEscape(Redacted), Redacted)
	return RedactText(s)
}

// redactQuery redacts a query or a form body, keeping the order of its
// parameters.
func redactQuery(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		name, _, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if n, err := url.QueryUnescape(name); err == nil && SecretName(n) {
			parts[i] = name + "=" + Redacted
		}
	}
	return strings.Join(parts, "&")
}

// RedactBody redacts a body by its content type: JSON fields and form
// parameters with secret names, and tokens in any text. A body that is
// not text is left out entirely: the result says its type and size
// instead (binary is true).
func RedactBody(contentType string, body []byte) (text string, binary bool) {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return RedactText(redactQuery(string(body))), false
	case mt == "application/json" || strings.HasSuffix(mt, "+json") || (mt == "" && json.Valid(bytes.TrimSpace(body))):
		var v any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			out, err := marshalJSON(redactJSON(v))
			if err == nil {
				return RedactText(string(out)), false
			}
		}
		return RedactText(string(body)), false
	case textual(mt, body):
		return RedactText(string(body)), false
	}
	return "", true
}

// textual reports whether a body reads as text.
func textual(mt string, body []byte) bool {
	switch {
	case strings.HasPrefix(mt, "text/"), strings.HasSuffix(mt, "+xml"), mt == "application/xml",
		mt == "application/javascript", mt == "application/graphql":
		return true
	case mt != "":
		return false
	}
	// No type: text when it is valid UTF-8 without control bytes.
	for _, r := range string(body) {
		if r == '�' || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') {
			return false
		}
	}
	return true
}

// redactJSON replaces the values of secret fields, at any depth: a
// string or a number (but a "code" number, which is mostly a status), not
// an object or a list, which are searched instead.
func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			switch x.(type) {
			case string:
				if SecretName(k) {
					t[k] = Redacted
				}
			case json.Number:
				if SecretName(k) && !strings.EqualFold(k, "code") {
					t[k] = Redacted
				}
			default:
				t[k] = redactJSON(x)
			}
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redactJSON(x)
		}
		return t
	}
	return v
}

// marshalJSON writes JSON without escaping HTML; encoding/json sorts map
// keys, so a redacted body reads the same each time.
func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
