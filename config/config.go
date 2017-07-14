package config

import (
	"net/http"
	"regexp"
	"time"
)

type Config struct {
	Auth        Auth
	Proxy       Proxy
	Registry    Registry
	Listen      []Listen
	Log         Log
	Metrics     Metrics
	UI          UI
	Runtime     Runtime
	ProfileMode string
	ProfilePath string
}

type CertSource struct {
	Name         string
	Type         string
	CertPath     string
	KeyPath      string
	ClientCAPath string
	CAUpgradeCN  string
	Refresh      time.Duration
	Header       http.Header
}

type Listen struct {
	Addr          string
	Proto         string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	CertSource    CertSource
	StrictMatch   bool
	TLSMinVersion uint16
	TLSMaxVersion uint16
	TLSCiphers    []uint16
}

type UI struct {
	Listen Listen
	Color  string
	Title  string
	Access string
}

type Proxy struct {
	Strategy              string
	Matcher               string
	NoRouteStatus         int
	MaxConn               int
	ShutdownWait          time.Duration
	DialTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	KeepAliveTimeout      time.Duration
	FlushInterval         time.Duration
	LocalIP               string
	ClientIPHeader        string
	TLSHeader             string
	TLSHeaderValue        string
	GZIPContentTypes      *regexp.Regexp
	RequestID             string
}

type Runtime struct {
	GOGC       int
	GOMAXPROCS int
}

type Circonus struct {
	APIKey   string
	APIApp   string
	APIURL   string
	CheckID  string
	BrokerID string
}

type Log struct {
	AccessFormat string
	AccessTarget string
	RoutesFormat string
}

type Metrics struct {
	Target       string
	Prefix       string
	Names        string
	Interval     time.Duration
	GraphiteAddr string
	StatsDAddr   string
	Circonus     Circonus
}

type Registry struct {
	Backend string
	Static  Static
	File    File
	Consul  Consul
	Timeout time.Duration
	Retry   time.Duration
}

type Static struct {
	Routes string
}

type File struct {
	Path string
}

type Consul struct {
	Addr               string
	Scheme             string
	Token              string
	KVPath             string
	TagPrefix          string
	Register           bool
	ServiceAddr        string
	ServiceName        string
	ServiceTags        []string
	ServiceStatus      []string
	CheckInterval      time.Duration
	CheckTimeout       time.Duration
	CheckScheme        string
	CheckTLSSkipVerify bool
}

type Auth struct {
	Type       string
	ConfigFile string
	Enabled    bool
}
