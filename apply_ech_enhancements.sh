#!/usr/bin/env bash
set -e

ROOT_DIR="/workspaces/PattNG"
cd "$ROOT_DIR"

echo "=== [1/6] Upgrading xray-core/transport/internet/tls/ech.go ==="
cat << 'EOGO' > "$ROOT_DIR/xray-core/transport/internet/tls/ech.go"
package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/net/http2"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/cryptobyte"
)

// parseExtendedECHSpec extracts optional "#pn=<override>&decoy=<domain>" metadata appended by the client
func parseExtendedECHSpec(raw string) (cleanSpec string, publicNameOverride string, decoyDomain string) {
	cleanSpec = strings.TrimSpace(raw)
	idx := strings.Index(cleanSpec, "#")
	if idx == -1 {
		return cleanSpec, "", ""
	}
	meta := cleanSpec[idx+1:]
	cleanSpec = strings.TrimSpace(cleanSpec[:idx])

	for _, kv := range strings.Split(meta, "&") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			continue
		}
		k := strings.TrimSpace(pair[0])
		v := strings.TrimSpace(pair[1])
		switch k {
		case "pn":
			publicNameOverride = v
		case "decoy":
			decoyDomain = v
		}
	}
	return cleanSpec, publicNameOverride, decoyDomain
}

// RewriteECHConfigListPublicName binary-patches the plaintext public_name inside draft-ietf-tls-esni (0xfe0d) ECHConfigList
func RewriteECHConfigListPublicName(rawList []byte, overrideRule string) []byte {
	overrideRule = strings.TrimSpace(overrideRule)
	if len(rawList) < 4 || overrideRule == "" {
		return rawList
	}

	s := cryptobyte.String(rawList)
	var listBody cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&listBody) || !s.Empty() {
		return rawList
	}

	var outList cryptobyte.Builder
	outList.AddUint16LengthPrefixed(func(listB *cryptobyte.Builder) {
		for !listBody.Empty() {
			var version uint16
			var configBody cryptobyte.String
			if !listBody.ReadUint16(&version) || !listBody.ReadUint16LengthPrefixed(&configBody) {
				listB.AddBytes(listBody)
				return
			}
			if version != 0xfe0d {
				listB.AddUint16(version)
				listB.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) {
					cb.AddBytes(configBody)
				})
				continue
			}

			origCopy := append([]byte(nil), configBody...)
			var keyConfig []byte
			var cipherSuites cryptobyte.String
			var maxNameLen uint8
			var pubNameBytes cryptobyte.String
			var extensions cryptobyte.String

			if len(configBody) < 5 {
				listB.AddUint16(version)
				listB.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) { cb.AddBytes(origCopy) })
				continue
			}
			pubKeyLen := int(binary.BigEndian.Uint16(configBody[3:5]))
			if len(configBody) < 5+pubKeyLen {
				listB.AddUint16(version)
				listB.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) { cb.AddBytes(origCopy) })
				continue
			}
			keyConfig = configBody[:5+pubKeyLen]
			configBody = configBody[5+pubKeyLen:]

			if !configBody.ReadUint16LengthPrefixed(&cipherSuites) ||
				!configBody.ReadUint8(&maxNameLen) ||
				!configBody.ReadUint8LengthPrefixed(&pubNameBytes) ||
				!configBody.ReadUint16LengthPrefixed(&extensions) {
				listB.AddUint16(version)
				listB.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) { cb.AddBytes(origCopy) })
				continue
			}

			origName := string(pubNameBytes)
			newName := origName
			if strings.EqualFold(overrideRule, "upper") || strings.EqualFold(overrideRule, "auto") {
				lastDot := strings.LastIndexByte(origName, '.')
				if lastDot != -1 && lastDot < len(origName)-1 {
					newName = origName[:lastDot+1] + strings.ToUpper(origName[lastDot+1:])
				} else {
					newName = strings.ToUpper(origName)
				}
			} else {
				newName = overrideRule
			}

			listB.AddUint16(version)
			listB.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) {
				cb.AddBytes(keyConfig)
				cb.AddUint16LengthPrefixed(func(csb *cryptobyte.Builder) {
					csb.AddBytes(cipherSuites)
				})
				cb.AddUint8(maxNameLen)
				cb.AddUint8LengthPrefixed(func(pnb *cryptobyte.Builder) {
					pnb.AddBytes([]byte(newName))
				})
				cb.AddUint16LengthPrefixed(func(extb *cryptobyte.Builder) {
					extb.AddBytes(extensions)
				})
			})
		}
	})

	patched, err := outList.Bytes()
	if err != nil || len(patched) == 0 {
		return rawList
	}
	return patched
}

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	var nameToQuery string
	if net.ParseAddress(config.ServerName).Family().IsDomain() {
		nameToQuery = config.ServerName
	}
	var DNSServer string

	// for server
	if len(c.EchServerKeys) != 0 {
		KeySets, err := ConvertToGoECHKeys(c.EchServerKeys)
		if err != nil {
			return errors.New("Failed to unmarshal ECHKeySetList: ", err)
		}
		config.EncryptedClientHelloKeys = KeySets
	}

	// for client
	if len(c.EchConfigList) != 0 {
		cleanList, pnOverride, decoyDomain := parseExtendedECHSpec(c.EchConfigList)

		defer func() {
			// if failed to get ECHConfig, use an invalid one to make connection fail
			if len(ECHConfig) == 0 {
				ECHConfig = []byte{1, 1, 4, 5, 1, 4}
			} else if pnOverride != "" {
				ECHConfig = RewriteECHConfigListPublicName(ECHConfig, pnOverride)
			}
			config.EncryptedClientHelloConfigList = ECHConfig
		}()

		// query config from dns
		if strings.Contains(cleanList, "://") {
			parts := strings.SplitN(cleanList, "+", 2)
			if len(parts) == 2 {
				nameToQuery = parts[0]
				DNSServer = parts[1]
			} else {
				DNSServer = parts[0]
			}
			if decoyDomain != "" {
				if strings.EqualFold(decoyDomain, "auto") {
					nameToQuery = "speed.cloudflare.com"
				} else {
					nameToQuery = decoyDomain
				}
			}
			if nameToQuery == "" {
				nameToQuery = "cloudflare-ech.com"
			}
			ECHConfig, err = QueryRecord(nameToQuery, DNSServer, c.EchSocketSettings)
			if err != nil {
				return errors.New("Failed to query ECH DNS record for domain: ", nameToQuery, " at server: ", DNSServer).Base(err)
			}
		} else {
			// direct base64 config
			ECHConfig, err = base64.StdEncoding.DecodeString(cleanList)
			if err != nil {
				return errors.New("Failed to unmarshal ECHConfigList: ", err)
			}
		}
	}

	return nil
}

type ECHConfigCache struct {
	configRecord atomic.Pointer[echConfigRecord]
	UpdateLock   sync.Mutex
}

type echConfigRecord struct {
	config []byte
	expire time.Time
}

var (
	GlobalECHConfigCache = utils.NewTypedSyncMap[string, *ECHConfigCache]()
	clientForECHDOH      = utils.NewTypedSyncMap[string, *http.Client]()
)

func ECHCacheKey(server, domain string, sockopt *internet.SocketConfig) string {
	return server + "|" + domain + "|" + fmt.Sprintf("%p", sockopt)
}

func (c *ECHConfigCache) Update(domain string, server string, isLockedUpdate bool, sockopt *internet.SocketConfig) ([]byte, error) {
	if !isLockedUpdate {
		c.UpdateLock.Lock()
		defer c.UpdateLock.Unlock()
	}
	configRecord := c.configRecord.Load()
	if configRecord.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "Cache hit for domain after double check: ", domain)
		return configRecord.config, nil
	}
	errors.LogDebug(context.Background(), "Trying to query ECH config for domain: ", domain, " with ECH server: ", server)
	echConfig, ttl, err := dnsQuery(server, domain, sockopt)
	if err != nil {
		return nil, err
	}
	configRecord = &echConfigRecord{
		config: echConfig,
		expire: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	c.configRecord.Store(configRecord)
	return configRecord.config, nil
}

func QueryRecord(domain string, server string, sockopt *internet.SocketConfig) ([]byte, error) {
	GlobalECHConfigCacheKey := ECHCacheKey(server, domain, sockopt)
	echConfigCache, ok := GlobalECHConfigCache.Load(GlobalECHConfigCacheKey)
	if !ok {
		echConfigCache = &ECHConfigCache{}
		echConfigCache.configRecord.Store(&echConfigRecord{})
		echConfigCache, _ = GlobalECHConfigCache.LoadOrStore(GlobalECHConfigCacheKey, echConfigCache)
	}
	configRecord := echConfigCache.configRecord.Load()
	if configRecord.expire.After(time.Now()) {
		errors.LogDebug(context.Background(), "Cache hit for domain: ", domain)
		return configRecord.config, nil
	}

	if configRecord.expire.IsZero() || configRecord.expire.Add(time.Hour*4).Before(time.Now()) {
		return echConfigCache.Update(domain, server, false, sockopt)
	} else {
		if echConfigCache.UpdateLock.TryLock() {
			go func() {
				defer echConfigCache.UpdateLock.Unlock()
				echConfigCache.Update(domain, server, true, sockopt)
			}()
		}
		return configRecord.config, nil
	}
}

func dnsQuery(server string, domain string, sockopt *internet.SocketConfig) ([]byte, uint32, error) {
	m := new(dns.Msg)
	var dnsResolve []byte
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "h2c://") {
		h2c := strings.HasPrefix(server, "h2c://")
		m.SetEdns0(4096, false)
		padding := &dns.EDNS0_PADDING{Padding: make([]byte, int(crypto.RandBetween(100, 300)))}
		if opt := m.IsEdns0(); opt != nil {
			opt.Option = append(opt.Option, padding)
		}
		m.Id = 0
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		var client *http.Client
		serverKey := ECHCacheKey(server, "", sockopt)
		if client, _ = clientForECHDOH.Load(serverKey); client == nil {
			tr := &http2.Transport{
				IdleConnTimeout: net.ConnIdleTimeout,
				ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					dest, err := net.ParseDestination(network + ":" + addr)
					if err != nil {
						return nil, err
					}
					dnsCtx := ctx
					if h2c {
						dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false)
						dnsCtx = session.ContextWithMitmServerName(dnsCtx, host)
					}
					var conn net.Conn
					conn, err = internet.DialSystem(dnsCtx, dest, sockopt)
					if err != nil {
						return nil, err
					}

					if !h2c {
						conn = utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
						if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
							return nil, err
						}
					}
					return conn, nil
				},
			}
			c := &http.Client{
				Timeout:   30 * time.Second,
				Transport: tr,
			}
			client, _ = clientForECHDOH.LoadOrStore(serverKey, c)
		}
		req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
		if err != nil {
			return nil, 0, err
		}
		req.URL.Scheme = "https"
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		utils.TryDefaultHeadersWith(req.Header, "fetch")
		req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, errors.New("query failed with response code:", resp.StatusCode)
		}
		dnsResolve = respBody
	} else if strings.HasPrefix(server, "tcp://") || strings.HasPrefix(server, "tcpfrag://") {
		// Fragmented TCP DNS query on port 53 to bypass UDP/53 DPI & QNAME inspection
		normalized := strings.Replace(server, "tcpfrag://", "tcp://", 1)
		tcpServerURL, err := url.Parse(normalized)
		if err != nil {
			return nil, 0, errors.New("failed to parse tcp dns server ", server, " for ECH: ", err)
		}
		if tcpServerURL.Port() == "" {
			tcpServerURL.Host = tcpServerURL.Host + ":53"
		}
		dest, err := net.ParseDestination("tcp:" + tcpServerURL.Host)
		if err != nil {
			return nil, 0, errors.New("failed to parse tcp destination ", tcpServerURL.Host, " for ECH: ", err)
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		conn, err := internet.DialSystem(dnsTimeoutCtx, dest, sockopt)
		if err != nil {
			return nil, 0, err
		}
		defer conn.Close()

		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		// RFC 1035 TCP DNS: 2-byte big-endian length prefix + DNS payload
		tcpFrame := make([]byte, 2+len(msg))
		binary.BigEndian.PutUint16(tcpFrame[:2], uint16(len(msg)))
		copy(tcpFrame[2:], msg)

		// Slice right through the QNAME (bytes 14..22) so DPI on port 53 never sees a contiguous domain name
		conn.SetDeadline(time.Now().Add(6 * time.Second))
		if len(tcpFrame) > 20 {
			_, _ = conn.Write(tcpFrame[:16])
			time.Sleep(15 * time.Millisecond)
			_, _ = conn.Write(tcpFrame[16:21])
			time.Sleep(15 * time.Millisecond)
			_, err = conn.Write(tcpFrame[21:])
		} else {
			_, err = conn.Write(tcpFrame)
		}
		if err != nil {
			return nil, 0, err
		}

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, 0, err
		}
		respLen := int(binary.BigEndian.Uint16(lenBuf))
		dnsResolve = make([]byte, respLen)
		if _, err := io.ReadFull(conn, dnsResolve); err != nil {
			return nil, 0, err
		}
	} else if strings.HasPrefix(server, "udp://") {
		udpServerURL, err := url.Parse(server)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", server, " for ECH: ", err)
		}
		if udpServerURL.Port() == "" {
			udpServerURL.Host = udpServerURL.Host + ":53"
		}
		dest, err := net.ParseDestination("udp" + ":" + udpServerURL.Host)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", udpServerURL.Host, " for ECH: ", err)
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := internet.DialSystem(dnsTimeoutCtx, dest, sockopt)
		if err != nil {
			return nil, 0, err
		}
		defer conn.Close()
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		conn.Write(msg)
		udpResponse := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(udpResponse)
		if err != nil {
			return nil, 0, err
		}
		dnsResolve = udpResponse[:n]
	}

	respMsg := new(dns.Msg)
	err := respMsg.Unpack(dnsResolve)
	if err != nil {
		return nil, 0, errors.New("failed to unpack dns response for ECH: ", err)
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok && len(echConfig.ECH) > 0 {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", answer.Header().Ttl)
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}
	return nil, 0, errors.New("no valid ECH config found in DNS response")
}

var ErrInvalidLen = errors.New("goech: invalid length")

func ConvertToGoECHKeys(data []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	s := cryptobyte.String(data)
	for !s.Empty() {
		if len(s) < 2 {
			return keys, ErrInvalidLen
		}
		keyLength := int(binary.BigEndian.Uint16(s[:2]))
		if len(s) < keyLength+4 {
			return keys, ErrInvalidLen
		}
		configLength := int(binary.BigEndian.Uint16(s[keyLength+2 : keyLength+4]))
		if len(s) < 2+keyLength+2+configLength {
			return keys, ErrInvalidLen
		}
		child := cryptobyte.String(s[:2+keyLength+2+configLength])
		var sk, config cryptobyte.String
		if !child.ReadUint16LengthPrefixed(&sk) || !child.ReadUint16LengthPrefixed(&config) || !child.Empty() {
			return keys, ErrInvalidLen
		}
		if !s.Skip(2 + keyLength + 2 + configLength) {
			return keys, ErrInvalidLen
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:     config,
			PrivateKey: sk,
		})
	}
	return keys, nil
}
EOGO

echo "=== [2/6] Pointing AndroidLibXrayLite/go.mod to local ../xray-core ==="
sed -i 's|replace github.com/xtls/xray-core => .*|replace github.com/xtls/xray-core => ../xray-core|g' "$ROOT_DIR/AndroidLibXrayLite/go.mod"

echo "=== [3/6] Adding String Resources for New ECH Fields in V2rayNG ==="
if ! grep -q "server_lab_ech_public_name" "$ROOT_DIR/V2rayNG/app/src/main/res/values/strings.xml"; then
    sed -i 's|<string name="server_lab_ech_config_list".*|<string name="server_lab_ech_config_list" translatable="false">echConfigList (Base64 / udp:// / tcpfrag:// / https://)</string>\n    <string name="server_lab_ech_public_name" translatable="false">echPublicName Override (e.g. UPPER or custom outer SNI)</string>\n    <string name="server_lab_ech_decoy_domain" translatable="false">echDecoyDomain (e.g. auto or CF decoy domain)</string>|g' "$ROOT_DIR/V2rayNG/app/src/main/res/values/strings.xml"
fi

echo "=== [4/6] Injecting echPublicName & echDecoyDomain into Kotlin Data/UI/Builder Layers ==="
# 1. ProfileItem.kt
if ! grep -q "var echPublicName:" "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/dto/entities/ProfileItem.kt"; then
    sed -i 's/var echOutbound: String? = null,/var echOutbound: String? = null,\n    var echPublicName: String? = null,\n    var echDecoyDomain: String? = null,/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/dto/entities/ProfileItem.kt"
fi

# 2. FmtBase.kt (Share URI import/export)
if ! grep -q "echPublicName" "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt"; then
    sed -i 's/config.echOutbound = queryParam\["echOutbound"\]/config.echOutbound = queryParam["echOutbound"]\n        config.echPublicName = queryParam["echPN"]\n        config.echDecoyDomain = queryParam["echDecoy"]/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt"
    sed -i 's/config.echOutbound?.nullIfBlank()?.let { dicQuery\["echOutbound"\] = it }/config.echOutbound?.nullIfBlank()?.let { dicQuery["echOutbound"] = it }\n        config.echPublicName?.nullIfBlank()?.let { dicQuery["echPN"] = it }\n        config.echDecoyDomain?.nullIfBlank()?.let { dicQuery["echDecoy"] = it }/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt"
fi

# 3. ServerUiState.kt
if ! grep -q "echPublicName:" "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/ServerUiState.kt"; then
    sed -i 's/echOutbound: String = "",/echOutbound: String = "",\n    echPublicName: String = "",\n    echDecoyDomain: String = "",/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/ServerUiState.kt"
    sed -i 's/var echOutbound by mutableStateOf(echOutbound)/var echOutbound by mutableStateOf(echOutbound)\n    var echPublicName by mutableStateOf(echPublicName)\n    var echDecoyDomain by mutableStateOf(echDecoyDomain)/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/ServerUiState.kt"
    sed -i 's/echOutbound = echOutbound.nullIfBlank(),/echOutbound = echOutbound.nullIfBlank(),\n            echPublicName = echPublicName.nullIfBlank(),\n            echDecoyDomain = echDecoyDomain.nullIfBlank(),/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/ServerUiState.kt"
    sed -i 's/echOutbound = initialConfig.echOutbound ?: "",/echOutbound = initialConfig.echOutbound ?: "",\n                echPublicName = initialConfig.echPublicName ?: "",\n                echDecoyDomain = initialConfig.echDecoyDomain ?: "",/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/ServerUiState.kt"
fi

# 4. BaseServerActivity.kt (Compose UI Form Fields)
if ! grep -q "server_lab_ech_public_name" "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/BaseServerActivity.kt"; then
    sed -i '/state.echOutbound,/{
n
s/{ state.echOutbound = it }/{ state.echOutbound = it }\n                )\n                FormTextField(\n                    stringResource(R.string.server_lab_ech_public_name),\n                    state.echPublicName,\n                    { state.echPublicName = it }\n                )\n                FormTextField(\n                    stringResource(R.string.server_lab_ech_decoy_domain),\n                    state.echDecoyDomain,\n                    { state.echDecoyDomain = it }/
}' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/ui/server/BaseServerActivity.kt"
fi

# 5. CoreOutboundBuilder.kt (Pass metadata seamlessly into echConfigList for Xray-core)
if ! grep -q "echPublicName" "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt"; then
    sed -i 's/echConfigList = profileItem.echConfigList.nullIfBlank(),/echConfigList = profileItem.echConfigList.nullIfBlank()?.let { baseEch ->\n                val meta = mutableListOf<String>()\n                profileItem.echPublicName?.trim()?.takeIf { it.isNotEmpty() }?.let { meta.add("pn=\$it") }\n                profileItem.echDecoyDomain?.trim()?.takeIf { it.isNotEmpty() }?.let { meta.add("decoy=\$it") }\n                if (meta.isEmpty()) baseEch else "\$baseEch#\${meta.joinToString("\&")}"\n            },/g' "$ROOT_DIR/V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt"
fi

echo "=== [5/6] Updating GitHub Actions Workflow (.github/workflows/build.yml) to compile custom libv2ray.aar ==="
# Replace downloading prebuilt AndroidLibXrayLite release with building from local AndroidLibXrayLite + xray-core
python3 - << 'PYEOF'
with open(".github/workflows/build.yml", "r") as f:
    content = f.read()

old_block = """    - name: Fetch AndroidLibXrayLite tag
      run: |
        pushd AndroidLibXrayLite
        CURRENT_TAG=$(git describe --tags --abbrev=0)
        echo "Current tag in this repo: $CURRENT_TAG"
        echo "CURRENT_TAG=$CURRENT_TAG" >> $GITHUB_ENV
        popd

    - name: Download libv2ray
      uses: robinraju/release-downloader@v1.13
      with:
        repository: 'patterniha/AndroidLibXrayLite'
        tag: ${{ env.CURRENT_TAG }}
        fileName: 'libv2ray.aar'
        out-file-path: V2rayNG/app/libs/"""

new_block = """    - name: Build Custom libv2ray.aar from local xray-core
      run: |
        export PATH=$PATH:$(go env GOPATH)/bin
        go install golang.org/x/mobile/cmd/gomobile@latest
        go install golang.org/x/mobile/cmd/gobind@latest
        pushd AndroidLibXrayLite
        mkdir -p assets data
        bash gen_assets.sh download
        cp -v data/*.dat assets/
        ANDROID_NDK_HOME=$NDK_HOME gomobile init
        go mod tidy
        ANDROID_NDK_HOME=$NDK_HOME gomobile bind -v -androidapi 29 -trimpath -ldflags='-s -w -buildid= -checklinkname=0' -o ../V2rayNG/app/libs/libv2ray.aar ./
        popd"""

if old_block in content:
    content = content.replace(old_block, new_block)
    with open(".github/workflows/build.yml", "w") as f:
        f.write(content)
    print("✅ Updated .github/workflows/build.yml to compile custom libv2ray.aar!")
else:
    print("ℹ️ build.yml already updated or pattern differed.")
PYEOF

echo "=== [6/6] Verifying Go Compilation of Enhanced Xray-Core ECH Package ==="
cd "$ROOT_DIR/xray-core"
go test -v ./transport/internet/tls -run TestNonExistentJustCompileCheck
echo "✅ Go Core (ech.go) compiled cleanly with zero errors!"
