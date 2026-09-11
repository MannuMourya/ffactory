package main

import (
	"fmt"
	"strings"
	"time"
)

type Config struct {
	URL            string
	Out            string
	Cookie         string
	CookieFile     string
	Bearer         string
	Session        string
	SaveSession    string
	LoginURL       string
	LoginJSON      string
	LoginUser      string
	LoginPass      string
	LoginUserField string
	LoginPassField string
	LoginExtra     kvList
	UserID         string
	Attrs          kvList
	Headers        headerList
	CacheDir       string
	JSLimit        int
	TimeoutSec     int
	Insecure       bool
	NoProbe        bool
	CompareAnon    bool
}

type kvList [][2]string

func (k *kvList) String() string { return "" }
func (k *kvList) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("expected key=value, got %q", v)
	}
	*k = append(*k, [2]string{v[:i], v[i+1:]})
	return nil
}

type headerList [][2]string

func (h *headerList) String() string { return "" }
func (h *headerList) Set(v string) error {
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return fmt.Errorf("expected 'Name: value', got %q", v)
	}
	name := strings.TrimSpace(v[:i])
	val := strings.TrimSpace(v[i+1:])
	*h = append(*h, [2]string{name, val})
	return nil
}

type Report struct {
	Target         string      `json:"target"`
	Authenticated  bool        `json:"authenticated"`
	DocumentStatus int         `json:"document_status"`
	Title          string      `json:"title"`
	FinalURL       string      `json:"final_url"`
	Platforms      []string    `json:"platforms"`
	ClientKeys     []ClientKey `json:"client_keys"`
	EvalURLs       []EvalURL   `json:"eval_urls"`
	Flags          []Flag      `json:"flags"`
	SecondaryHosts []string    `json:"secondary_hosts"`
	ProductNames   []string    `json:"product_names"`
	JSBundles      []string    `json:"js_bundles"`
	AuthOnlyFlags  []string    `json:"auth_only_flags,omitempty"`
	AnonOnlyFlags  []string    `json:"anon_only_flags,omitempty"`
	ProbeResults   []Probe     `json:"probe_results,omitempty"`
	Notes          []string    `json:"notes,omitempty"`
	ScannedAt      time.Time   `json:"scanned_at"`
}

type ClientKey struct {
	Platform string `json:"platform"`
	Key      string `json:"key"`
	Source   string `json:"source"`
}

type EvalURL struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Source   string `json:"source"`
}

type Flag struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
	On     *bool  `json:"on,omitempty"`
}

type Probe struct {
	Platform  string `json:"platform"`
	URL       string `json:"url"`
	Status    int    `json:"status"`
	Note      string `json:"note,omitempty"`
	FlagCount int    `json:"flag_count,omitempty"`
}
