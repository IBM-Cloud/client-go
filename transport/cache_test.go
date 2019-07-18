/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

func TestDisableCache(t *testing.T) {

	tlsCfg1 := &Config{
		TLS: TLSConfig{CAData: []byte{1}},
	}
	tlsCfg2 := &Config{
		TLS:                   TLSConfig{CAData: []byte{2}},
		DisableTransportCache: true,
	}

	// expected to be cached and create a new entry
	transport1, err := tlsCache.get(tlsCfg1)
	if err != nil {
		t.Errorf("Unexpected error getting transport: %v", err)
	}
	if transport1 == nil {
		t.Error("Unexpected nil transport")
	}
	if len(tlsCache.transports) != 1 {
		t.Errorf("Expected cache to be of size 1, but it was %v", len(tlsCache.transports))
	}

	// retrieve existing cache entry
	transport2, err := tlsCache.get(tlsCfg1)
	if err != nil {
		t.Errorf("Unexpected error getting transport: %v", err)
	}
	if transport2 == nil {
		t.Error("Unexpected nil transport")
	}
	if len(tlsCache.transports) != 1 {
		t.Errorf("Expected cache to be of size 1, but it was %v", len(tlsCache.transports))
	}
	if transport1 != transport2 {
		t.Errorf("cached transports not equal")
	}

	// disable caching for same key parameters
	tlsCfg1.DisableTransportCache = true
	transport3, err := tlsCache.get(tlsCfg1)
	if err != nil {
		t.Errorf("Unexpected error getting transport: %v", err)
	}
	if transport3 == nil {
		t.Error("Unexpected nil transport")
	}
	if len(tlsCache.transports) != 1 {
		t.Errorf("Expected cache to be of size 1, but it was %v", len(tlsCache.transports))
	}
	if transport1 == transport3 {
		t.Errorf("transports should not be equal when caching is disabled")
	}

	// key with new parameters, caching disabled
	transport4, err := tlsCache.get(tlsCfg2)
	if err != nil {
		t.Errorf("Unexpected error getting transport: %v", err)
	}
	if transport4 == nil {
		t.Error("Unexpected nil transport")
	}
	if len(tlsCache.transports) != 1 {
		t.Errorf("Expected cache to be of size 1, but it was %v", len(tlsCache.transports))
	}
}

func TestTLSConfigKey(t *testing.T) {
	// Make sure config fields that don't affect the tls config don't affect the cache key
	identicalConfigurations := map[string]*Config{
		"empty":          {},
		"basic":          {Username: "bob", Password: "password"},
		"bearer":         {BearerToken: "token"},
		"user agent":     {UserAgent: "useragent"},
		"transport":      {Transport: http.DefaultTransport},
		"wrap transport": {WrapTransport: func(http.RoundTripper) http.RoundTripper { return nil }},
	}
	for nameA, valueA := range identicalConfigurations {
		for nameB, valueB := range identicalConfigurations {
			keyA, err := tlsConfigKey(valueA)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameA, err)
				continue
			}
			keyB, err := tlsConfigKey(valueB)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameB, err)
				continue
			}
			if keyA != keyB {
				t.Errorf("Expected identical cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				continue
			}
		}
	}

	// Make sure config fields that affect the tls config affect the cache key
	dialer := net.Dialer{}
	getCert := func() (*tls.Certificate, error) { return nil, nil }
	uniqueConfigurations := map[string]*Config{
		"no tls":   {},
		"dialer":   {Dial: dialer.DialContext},
		"dialer2":  {Dial: func(ctx context.Context, network, address string) (net.Conn, error) { return nil, nil }},
		"insecure": {TLS: TLSConfig{Insecure: true}},
		"cadata 1": {TLS: TLSConfig{CAData: []byte{1}}},
		"cadata 2": {TLS: TLSConfig{CAData: []byte{2}}},
		"cert 1, key 1": {
			TLS: TLSConfig{
				CertData: []byte{1},
				KeyData:  []byte{1},
			},
		},
		"cert 1, key 1, servername 1": {
			TLS: TLSConfig{
				CertData:   []byte{1},
				KeyData:    []byte{1},
				ServerName: "1",
			},
		},
		"cert 1, key 1, servername 2": {
			TLS: TLSConfig{
				CertData:   []byte{1},
				KeyData:    []byte{1},
				ServerName: "2",
			},
		},
		"cert 1, key 2": {
			TLS: TLSConfig{
				CertData: []byte{1},
				KeyData:  []byte{2},
			},
		},
		"cert 2, key 1": {
			TLS: TLSConfig{
				CertData: []byte{2},
				KeyData:  []byte{1},
			},
		},
		"cert 2, key 2": {
			TLS: TLSConfig{
				CertData: []byte{2},
				KeyData:  []byte{2},
			},
		},
		"cadata 1, cert 1, key 1": {
			TLS: TLSConfig{
				CAData:   []byte{1},
				CertData: []byte{1},
				KeyData:  []byte{1},
			},
		},
		"getCert1": {
			TLS: TLSConfig{
				KeyData: []byte{1},
				GetCert: getCert,
			},
		},
		"getCert2": {
			TLS: TLSConfig{
				KeyData: []byte{1},
				GetCert: func() (*tls.Certificate, error) { return nil, nil },
			},
		},
		"getCert1, key 2": {
			TLS: TLSConfig{
				KeyData: []byte{2},
				GetCert: getCert,
			},
		},
		"http2, http1.1": {TLS: TLSConfig{NextProtos: []string{"h2", "http/1.1"}}},
		"http1.1-only":   {TLS: TLSConfig{NextProtos: []string{"http/1.1"}}},
	}
	for nameA, valueA := range uniqueConfigurations {
		for nameB, valueB := range uniqueConfigurations {
			keyA, err := tlsConfigKey(valueA)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameA, err)
				continue
			}
			keyB, err := tlsConfigKey(valueB)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameB, err)
				continue
			}

			// Make sure we get the same key on the same config
			if nameA == nameB {
				if keyA != keyB {
					t.Errorf("Expected identical cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				}
				continue
			}

			if keyA == keyB {
				t.Errorf("Expected unique cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				continue
			}
		}
	}
}
