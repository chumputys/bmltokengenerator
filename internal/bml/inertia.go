package bml

import (
	"bytes"
	"encoding/json"
	"fmt"

	"golang.org/x/net/html"
)

// pageProps is the subset of BML's Inertia page props the login flow reads.
type pageProps struct {
	Channels []OTPChannel   `json:"channels"`
	Profiles []Profile      `json:"profiles"`
	Errors   map[string]any `json:"errors"`
	Flash    map[string]any `json:"flash"`
}

// message returns the most useful human-readable error carried by the page,
// or "" when there is none.
func (p pageProps) message() string {
	if msg, ok := p.Flash["message"].(string); ok && msg != "" {
		return msg
	}
	for _, v := range p.Errors {
		switch e := v.(type) {
		case string:
			if e != "" {
				return e
			}
		case []any:
			if len(e) > 0 {
				if s, ok := e[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

// extractProps pulls Inertia page props out of the data-page attribute on
// the #app div. The tokenizer unescapes attribute entities for us.
func extractProps(body []byte) (pageProps, error) {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return pageProps{}, fmt.Errorf("%w: page has no #app element", ErrUnexpectedResponse)
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "div" || !hasAttr {
				continue
			}
			var id, dataPage string
			for more := true; more; {
				var key, val []byte
				key, val, more = z.TagAttr()
				switch string(key) {
				case "id":
					id = string(val)
				case "data-page":
					dataPage = string(val)
				}
			}
			if id != "app" {
				continue
			}
			if dataPage == "" {
				return pageProps{}, fmt.Errorf("%w: #app element has no page data", ErrUnexpectedResponse)
			}
			var page struct {
				Props json.RawMessage `json:"props"`
			}
			if err := json.Unmarshal([]byte(dataPage), &page); err != nil {
				return pageProps{}, fmt.Errorf("%w: invalid page data: %v", ErrUnexpectedResponse, err)
			}
			var props pageProps
			if len(page.Props) > 0 {
				if err := json.Unmarshal(page.Props, &props); err != nil {
					return pageProps{}, fmt.Errorf("%w: invalid page props: %v", ErrUnexpectedResponse, err)
				}
			}
			return props, nil
		}
	}
}
