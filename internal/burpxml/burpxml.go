// Package burpxml exports and imports Burp Suite's XML item format
// (<items><item>…base64 request/response…</item></items>).
package burpxml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

type xmlItems struct {
	XMLName xml.Name  `xml:"items"`
	Items   []xmlItem `xml:"item"`
}

type xmlItem struct {
	Time      string `xml:"time"`
	URL       string `xml:"url"`
	Host      string `xml:"host"`
	Port      string `xml:"port"`
	Protocol  string `xml:"protocol"`
	Method    string `xml:"method"`
	Path      string `xml:"path"`
	Extension string `xml:"extension"`
	Status    string `xml:"status"`
	Mimetype  string `xml:"mimetype"`
	Request   []byte `xml:"request"`
	Response  []byte `xml:"response"`
	Comment   string `xml:"comment"`
}

// Export renders flows in Burp XML form. Request/response payloads are the
// exact rendered wire form, base64-encoded.
func Export(fs []*flows.Flow) ([]byte, error) {
	out := xmlItems{}
	for _, f := range fs {
		if f == nil || f.Request == nil || f.Tunnel {
			continue
		}
		status := ""
		mime := ""
		if f.Response != nil {
			status = fmt.Sprintf("%d", f.Response.Status)
			if v, ok := f.Response.Headers.Get("Content-Type"); ok {
				mime = v
			}
		}
		req := flows.RenderRequest(f.Request)
		var resp []byte
		if f.Response != nil {
			resp = flows.RenderResponse(f.Response)
		}
		out.Items = append(out.Items, xmlItem{
			Time:     f.Started.UTC().Format(time.RFC1123),
			URL:      f.Request.URL(),
			Host:     f.Request.Host,
			Port:     fmt.Sprintf("%d", orDef(f.Request.Port, 80)),
			Protocol: f.Request.Scheme,
			Method:   f.Request.Method,
			Path:     f.Request.Path,
			Status:   status,
			Mimetype: mime,
			Request:  []byte(base64.StdEncoding.EncodeToString(req)),
			Response: []byte(base64.StdEncoding.EncodeToString(resp)),
			Comment:  f.Comment,
		})
	}
	var sb strings.Builder
	sb.WriteString(xml.Header)
	enc := xml.NewEncoder(&sb)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	sb.WriteString("\n")
	return []byte(sb.String()), nil
}

func orDef(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// ImportedItem is one decoded entry.
type ImportedItem struct {
	Method   string
	Scheme   string
	Host     string
	Port     int
	Path     string
	Status   int
	Request  []byte
	Response []byte
	Comment  string
}

// Import parses a Burp XML document.
func Import(data []byte) ([]ImportedItem, error) {
	var doc xmlItems
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("burp xml: %w", err)
	}
	out := []ImportedItem{}
	for _, it := range doc.Items {
		req, err := base64.StdEncoding.DecodeString(string(it.Request))
		if err != nil {
			continue // tolerate partial exports
		}
		scheme := it.Protocol
		if scheme == "" {
			scheme = "http"
		}
		port := 0
		fmt.Sscanf(it.Port, "%d", &port)
		resp, _ := base64.StdEncoding.DecodeString(string(it.Response))
		out = append(out, ImportedItem{
			Method: it.Method, Scheme: scheme, Host: it.Host, Port: port,
			Path: it.Path, Request: req, Response: resp, Comment: it.Comment,
		})
	}
	return out, nil
}
