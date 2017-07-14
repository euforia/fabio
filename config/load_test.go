package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pascaldekloe/goe/verify"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		desc    string
		args    []string
		environ []string
		path    string
		data    string
		cfg     func(*Config) *Config
		err     error
	}{
		{
			args: []string{"-v"},
			cfg:  func(cfg *Config) *Config { return nil },
		},
		{
			args: []string{"--version"},
			cfg:  func(cfg *Config) *Config { return nil },
		},
		{
			desc: "-v with other args",
			args: []string{"-a", "-v", "-b"},
			cfg:  func(cfg *Config) *Config { return nil },
		},
		{
			desc: "--version with other args",
			args: []string{"-a", "--version", "-b"},
			cfg:  func(cfg *Config) *Config { return nil },
		},
		{
			desc: "default config",
			cfg:  func(cfg *Config) *Config { return cfg },
		},
		{
			args: []string{"-profile.mode", "foo"},
			cfg: func(cfg *Config) *Config {
				cfg.ProfileMode = "foo"
				return cfg
			},
		},
		{
			args: []string{"-profile.path", "foo"},
			cfg: func(cfg *Config) *Config {
				cfg.ProfilePath = "foo"
				return cfg
			},
		},
		{
			args: []string{"-proxy.addr", ":5555"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			args: []string{"-proxy.addr", ":5555;proto=http"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			args: []string{"-proxy.addr", ":5555;proto=tcp"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "tcp"}}
				return cfg
			},
		},
		{
			args: []string{"-proxy.addr", ":5555;proto=tcp+sni"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "tcp+sni"}}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with tls configs",
			args: []string{"-proxy.addr", `:5555;rt=1s;wt=2s;tlsmin=0x0300;tlsmax=0x305;tlsciphers="0x123,0x456"`},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{
					{
						Addr:          ":5555",
						Proto:         "http",
						ReadTimeout:   1 * time.Second,
						WriteTimeout:  2 * time.Second,
						TLSMinVersion: 0x300,
						TLSMaxVersion: 0x305,
						TLSCiphers:    []uint16{0x123, 0x456},
					},
				}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with named tls configs",
			args: []string{"-proxy.addr", `:5555;rt=1s;wt=2s;tlsmin=tls10;tlsmax=TLS11;tlsciphers="TLS_RSA_WITH_RC4_128_SHA,tls_ecdhe_ecdsa_with_aes_256_gcm_sha384"`},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{
					{
						Addr:          ":5555",
						Proto:         "http",
						ReadTimeout:   1 * time.Second,
						WriteTimeout:  2 * time.Second,
						TLSMinVersion: tls.VersionTLS10,
						TLSMaxVersion: tls.VersionTLS11,
						TLSCiphers:    []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
					},
				}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with file cert source",
			args: []string{"-proxy.addr", ":5555;cs=name", "-proxy.cs", "cs=name;type=file;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{Listen{Addr: ":5555", Proto: "https"}}
				cfg.Listen[0].CertSource = CertSource{Name: "name", Type: "file", CertPath: "value"}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with path cert source",
			args: []string{"-proxy.addr", ":5555;cs=name", "-proxy.cs", "cs=name;type=path;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{Listen{Addr: ":5555", Proto: "https"}}
				cfg.Listen[0].CertSource = CertSource{Name: "name", Type: "path", CertPath: "value", Refresh: 3 * time.Second}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with http cert source",
			args: []string{"-proxy.addr", ":5555;cs=name", "-proxy.cs", "cs=name;type=http;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{Listen{Addr: ":5555", Proto: "https"}}
				cfg.Listen[0].CertSource = CertSource{Name: "name", Type: "http", CertPath: "value", Refresh: 3 * time.Second}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with consul cert source",
			args: []string{"-proxy.addr", ":5555;cs=name", "-proxy.cs", "cs=name;type=consul;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{Listen{Addr: ":5555", Proto: "https"}}
				cfg.Listen[0].CertSource = CertSource{Name: "name", Type: "consul", CertPath: "value"}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with vault cert source",
			args: []string{"-proxy.addr", ":5555;cs=name", "-proxy.cs", "cs=name;type=vault;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{Listen{Addr: ":5555", Proto: "https"}}
				cfg.Listen[0].CertSource = CertSource{Name: "name", Type: "vault", CertPath: "value", Refresh: 3 * time.Second}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with cert source",
			args: []string{"-proxy.addr", ":5555;cs=name;strictmatch=true", "-proxy.cs", "cs=name;type=path;cert=foo;clientca=bar;refresh=2s;hdr=a: b;caupgcn=furb"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{
					Listen{
						Addr:        ":5555",
						Proto:       "https",
						StrictMatch: true,
						CertSource: CertSource{
							Name:         "name",
							Type:         "path",
							CertPath:     "foo",
							ClientCAPath: "bar",
							Refresh:      2 * time.Second,
							Header:       http.Header{"A": []string{"b"}},
							CAUpgradeCN:  "furb",
						},
					},
				}
				return cfg
			},
		},
		{
			desc: "-proxy.addr with cert source with full options",
			args: []string{"-proxy.addr", ":5555;cs=name;strictmatch=true;proto=https", "-proxy.cs", "cs=name;type=path;cert=foo;clientca=bar;refresh=2s;hdr=a: b;caupgcn=furb"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{
					Listen{
						Addr:        ":5555",
						Proto:       "https",
						StrictMatch: true,
						CertSource: CertSource{
							Name:         "name",
							Type:         "path",
							CertPath:     "foo",
							ClientCAPath: "bar",
							Refresh:      2 * time.Second,
							Header:       http.Header{"A": []string{"b"}},
							CAUpgradeCN:  "furb",
						},
					},
				}
				return cfg
			},
		},
		{
			desc: "issue 305",
			args: []string{
				"-proxy.addr", ":443;cs=consul-cs,:80,:2375;proto=tcp+sni",
				"-proxy.cs", "cs=consul-cs;type=consul;cert=http://localhost:8500/v1/kv/ssl?token=token",
			},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{
					Listen{Addr: ":443", Proto: "https"},
					Listen{Addr: ":80", Proto: "http"},
					Listen{Addr: ":2375", Proto: "tcp+sni"},
				}
				cfg.Listen[0].CertSource = CertSource{
					Name:     "consul-cs",
					Type:     "consul",
					CertPath: "http://localhost:8500/v1/kv/ssl?token=token",
				}
				return cfg
			},
		},
		{
			args: []string{"-proxy.localip", "1.2.3.4"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.LocalIP = "1.2.3.4"
				return cfg
			},
		},
		{
			args: []string{"-proxy.strategy", "rnd"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.Strategy = "rnd"
				return cfg
			},
		},
		{
			args: []string{"-proxy.strategy", "rr"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.Strategy = "rr"
				return cfg
			},
		},
		{
			args: []string{"-proxy.matcher", "prefix"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.Matcher = "prefix"
				return cfg
			},
		},
		{
			args: []string{"-proxy.matcher", "glob"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.Matcher = "glob"
				return cfg
			},
		},
		{
			args: []string{"-proxy.noroutestatus", "555"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.NoRouteStatus = 555
				return cfg
			},
		},
		{
			args: []string{"-proxy.shutdownwait", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.ShutdownWait = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-proxy.responseheadertimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.ResponseHeaderTimeout = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-proxy.keepalivetimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.KeepAliveTimeout = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-proxy.dialtimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.DialTimeout = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-proxy.readtimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":9999", Proto: "http", ReadTimeout: 5 * time.Millisecond}}
				return cfg
			},
		},
		{
			args: []string{"-proxy.writetimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":9999", Proto: "http", WriteTimeout: 5 * time.Millisecond}}
				return cfg
			},
		},
		{
			args: []string{"-proxy.flushinterval", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.FlushInterval = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-proxy.maxconn", "555"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.MaxConn = 555
				return cfg
			},
		},
		{
			args: []string{"-proxy.header.clientip", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.ClientIPHeader = "value"
				return cfg
			},
		},
		{
			args: []string{"-proxy.header.tls", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.TLSHeader = "value"
				return cfg
			},
		},
		{
			args: []string{"-proxy.header.tls.value", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.TLSHeaderValue = "value"
				return cfg
			},
		},
		{
			args: []string{"-proxy.header.requestid", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.RequestID = "value"
				return cfg
			},
		},
		{
			args: []string{"-proxy.gzip.contenttype", `^text/.*$`},
			cfg: func(cfg *Config) *Config {
				cfg.Proxy.GZIPContentTypes = regexp.MustCompile(`^text/.*$`)
				return cfg
			},
		},
		{
			args: []string{"-proxy.log.routes", "foobar"},
			cfg: func(cfg *Config) *Config {
				cfg.Log.RoutesFormat = "foobar"
				return cfg
			},
		},
		{
			args: []string{"-registry.backend", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Backend = "value"
				return cfg
			},
		},
		{
			args: []string{"-registry.timeout", "5s"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Timeout = 5 * time.Second
				return cfg
			},
		},
		{
			args: []string{"-registry.retry", "500ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Retry = 500 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-registry.file.path", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.File.Path = "value"
				return cfg
			},
		},
		{
			args: []string{"-registry.static.routes", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Static.Routes = "value"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.addr", "1.2.3.4:5555"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Addr = "1.2.3.4:5555"
				cfg.Registry.Consul.Scheme = "http"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.addr", "http://1.2.3.4:5555/"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Addr = "1.2.3.4:5555"
				cfg.Registry.Consul.Scheme = "http"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.addr", "https://1.2.3.4:5555/"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Addr = "1.2.3.4:5555"
				cfg.Registry.Consul.Scheme = "https"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.addr", "HTTPS://1.2.3.4:5555/"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Addr = "1.2.3.4:5555"
				cfg.Registry.Consul.Scheme = "https"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.token", "some-token"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Token = "some-token"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.kvpath", "/some/path"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.KVPath = "/some/path"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.tagprefix", "p-"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.TagPrefix = "p-"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.enabled=false"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.Register = false
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.addr", "1.2.3.4:5555"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.ServiceAddr = "1.2.3.4:5555"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.name", "fab"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.ServiceName = "fab"
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.checkTLSSkipVerify=true"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.CheckTLSSkipVerify = true
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.tags", "a, b, c, "},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.ServiceTags = []string{"a", "b", "c"}
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.checkInterval", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.CheckInterval = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.register.checkTimeout", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.CheckTimeout = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-registry.consul.service.status", "a, b, "},
			cfg: func(cfg *Config) *Config {
				cfg.Registry.Consul.ServiceStatus = []string{"a", "b"}
				return cfg
			},
		},
		{
			args: []string{"-log.access.format", "foobar"},
			cfg: func(cfg *Config) *Config {
				cfg.Log.AccessFormat = "foobar"
				return cfg
			},
		},
		{
			args: []string{"-log.access.target", "foobar"},
			cfg: func(cfg *Config) *Config {
				cfg.Log.AccessTarget = "foobar"
				return cfg
			},
		},
		{
			args: []string{"-log.routes.format", "foobar"},
			cfg: func(cfg *Config) *Config {
				cfg.Log.RoutesFormat = "foobar"
				return cfg
			},
		},
		{
			args: []string{"-metrics.target", "some-target"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Target = "some-target"
				return cfg
			},
		},
		{
			args: []string{"-metrics.prefix", "some-prefix"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Prefix = "some-prefix"
				return cfg
			},
		},
		{
			args: []string{"-metrics.names", "some names"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Names = "some names"
				return cfg
			},
		},
		{
			args: []string{"-metrics.interval", "5ms"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Interval = 5 * time.Millisecond
				return cfg
			},
		},
		{
			args: []string{"-metrics.graphite.addr", "1.2.3.4:5555"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.GraphiteAddr = "1.2.3.4:5555"
				return cfg
			},
		},
		{
			args: []string{"-metrics.statsd.addr", "1.2.3.4:5555"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.StatsDAddr = "1.2.3.4:5555"
				return cfg
			},
		},
		{
			args: []string{"-metrics.circonus.apiapp", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Circonus.APIApp = "value"
				return cfg
			},
		},
		{
			args: []string{"-metrics.circonus.apikey", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Circonus.APIKey = "value"
				return cfg
			},
		},
		{
			args: []string{"-metrics.circonus.apiurl", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Circonus.APIURL = "value"
				return cfg
			},
		},
		{
			args: []string{"-metrics.circonus.brokerid", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Circonus.BrokerID = "value"
				return cfg
			},
		},
		{
			args: []string{"-metrics.circonus.checkid", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.Metrics.Circonus.CheckID = "value"
				return cfg
			},
		},
		{
			args: []string{"-runtime.gogc", "555"},
			cfg: func(cfg *Config) *Config {
				cfg.Runtime.GOGC = 555
				return cfg
			},
		},
		{
			args: []string{"-runtime.gomaxprocs", "555"},
			cfg: func(cfg *Config) *Config {
				cfg.Runtime.GOMAXPROCS = 555
				return cfg
			},
		},
		{
			args: []string{"-ui.access", "ro"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Access = "ro"
				return cfg
			},
		},
		{
			args: []string{"-ui.access", "rw"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Access = "rw"
				return cfg
			},
		},
		{
			args: []string{"-ui.addr", "1.2.3.4:5555"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Listen.Addr = "1.2.3.4:5555"
				cfg.UI.Listen.Proto = "http"
				return cfg
			},
		},
		{
			args: []string{"-ui.addr", ":9998;cs=ui", "-proxy.cs", "cs=ui;type=file;cert=value"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Listen.Addr = ":9998"
				cfg.UI.Listen.Proto = "https"
				cfg.UI.Listen.CertSource.Name = "ui"
				cfg.UI.Listen.CertSource.Type = "file"
				cfg.UI.Listen.CertSource.CertPath = "value"
				cfg.Registry.Consul.CheckScheme = "https"
				return cfg
			},
		},
		{
			args: []string{"-ui.color", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Color = "value"
				return cfg
			},
		},
		{
			args: []string{"-ui.title", "value"},
			cfg: func(cfg *Config) *Config {
				cfg.UI.Title = "value"
				return cfg
			},
		},
		{
			desc: "ignore aws.apigw.cert.cn",
			args: []string{"-aws.apigw.cert.cn", "value"},
			cfg:  func(cfg *Config) *Config { return cfg },
		},

		// config file
		{
			desc:    "config from environ",
			environ: []string{"FABIO_proxy_addr=:6666"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":6666", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "config from url",
			args: []string{"-cfg", "URL"},
			path: "http",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "config from file I",
			args: []string{"-cfg", "/tmp/fabio-config-test"},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "config from file II",
			args: []string{"-cfg=/tmp/fabio-config-test"},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "config from file III",
			args: []string{"-cfg='/tmp/fabio-config-test'"},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "config from file IV",
			args: []string{"-cfg=\"/tmp/fabio-config-test\""},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},

		// precedence rules
		{
			desc: "cmdline over config file I",
			args: []string{"-cfg", "/tmp/fabio-config-test", "-proxy.addr", ":6666"},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":6666", Proto: "http"}}
				return cfg
			},
		},
		{
			desc: "cmdline over config file II",
			args: []string{"-proxy.addr", ":6666", "-cfg", "/tmp/fabio-config-test"},
			path: "/tmp/fabio-config-test",
			data: "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":6666", Proto: "http"}}
				return cfg
			},
		},
		{
			desc:    "environ over config file",
			args:    []string{"-cfg", "/tmp/fabio-config-test"},
			environ: []string{"FABIO_proxy_addr=:6666"},
			path:    "/tmp/fabio-config-test",
			data:    "proxy.addr = :5555",
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":6666", Proto: "http"}}
				return cfg
			},
		},
		{
			desc:    "cmdline over environ",
			args:    []string{"-proxy.addr", ":5555"},
			environ: []string{"FABIO_proxy_addr=:6666"},
			cfg: func(cfg *Config) *Config {
				cfg.Listen = []Listen{{Addr: ":5555", Proto: "http"}}
				return cfg
			},
		},

		// errors
		{
			desc: "-proxy.addr with unknown cert source 'foo'",
			args: []string{"-proxy.addr", ":5555;cs=foo"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("unknown certificate source \"foo\""),
		},
		{
			desc: "-proxy.addr with unknown proto 'foo'",
			args: []string{"-proxy.addr", ":5555;proto=foo"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("unknown protocol \"foo\""),
		},
		{
			desc: "-proxy.addr with proto 'https' requires cert source",
			args: []string{"-proxy.addr", ":5555;proto=https"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("proto 'https' requires cert source"),
		},
		{
			desc: "-proxy.addr with cert source and proto 'http' requires proto 'https' or 'tcp'",
			args: []string{"-proxy.addr", ":5555;cs=name;proto=http", "-proxy.cs", "cs=name;type=path;cert=value"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("cert source requires proto 'https' or 'tcp'"),
		},
		{
			desc: "-proxy.addr with cert source and proto 'tcp+sni' requires proto 'https' or 'tcp'",
			args: []string{"-proxy.addr", ":5555;cs=name;proto=tcp+sni", "-proxy.cs", "cs=name;type=path;cert=value"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("cert source requires proto 'https' or 'tcp'"),
		},
		{
			desc: "-auth with type",
			args: []string{"-auth", ";file=/path/to/config"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("auth type required"),
		},
		{
			desc: "-auth with type and empty config file",
			args: []string{"-auth", "jwt;file="},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errors.New("auth config file required"),
		},
		{
			desc: "-auth with type and missing file param",
			args: []string{"-auth", "jwt;"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errInvalidConfig,
		},
		{
			desc: "-auth with too many args",
			args: []string{"-auth", "jwt;file=foo;extra=bar"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errInvalidConfig,
		},
		{
			args: []string{"-cfg"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errInvalidConfig,
		},
		{
			args: []string{"-cfg=''"},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errInvalidConfig,
		},
		{
			args: []string{"-cfg=\"\""},
			cfg:  func(cfg *Config) *Config { return nil },
			err:  errInvalidConfig,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop var

		if tt.desc == "" {
			tt.desc = strings.Join(tt.args, " ")
		}

		t.Run(tt.desc, func(t *testing.T) {
			// start a web server or write data to a file if tt.path is set
			switch {
			case tt.path == "http":
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprint(w, tt.data)
				}))
				defer srv.Close()

				// replace 'URL' with the actual server url in the command line args
				for i := range tt.args {
					tt.args[i] = strings.Replace(tt.args[i], "URL", srv.URL, -1)
				}

			case tt.path != "":
				if err := ioutil.WriteFile(tt.path, []byte(tt.data), 0600); err != nil {
					t.Fatalf("error writing file: %s", err)
				}
				defer os.Remove(tt.path)
			}

			// config parser expects the exe name to be the first argument
			cfg, err := Load(append([]string{"fabio"}, tt.args...), tt.environ)
			if got, want := err, tt.err; !reflect.DeepEqual(got, want) {
				t.Fatalf("got error %v want %v", got, want)
			}

			// limit the amount of code we have to write per test:
			// each test has a function which augments a pre-configured
			// config structure which is pre-filled with the defaults.
			clone := new(Config)
			*clone = *defaultConfig
			clone.Listen = []Listen{{Addr: ":9999", Proto: "http"}}
			got, want := cfg, tt.cfg(clone)
			verify.Values(t, "", got, want)
		})
	}
}
