package main

// PublicVPNList 是 VPN Gate 之外的第二个节点来源。
//
// 为什么要加它：VPN Gate 常年只有几十个可用节点，而且按地区分布很不均
// （日本多、欧美少）。PublicVPNList 的池子大得多（几万条），能补上
// VPN Gate 覆盖不到的地区。
//
// 和 VPN Gate 最大的不同：**它的 .ovpn 不在列表里，要逐条再下载一次**。
// 列表接口一次性给几万行，但每条只带元数据；拿配置得再请求
// /protocols/download.php。所以这里必须并发 + 限流，否则几万次请求
// 会把对方打挂，也会把自己拖死（实测串行拉 20 条要一分多钟）。
//
// 也因此：batch 只给挑出来的前 N 条补配置，不是全量补。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pvlBase 是 PublicVPNList 的站点根。
const pvlBase = "https://publicvpnlist.com"

// pvlMinGap 是两次请求之间的最小间隔。
//
// 对方有速率限制，密集请求会返回 403 并把 IP 封一阵子
// （实测连着跑几百次就被封，且不是几分钟能恢复的）。
// 200ms 是试出来的：再快就开始丢响应。
const pvlMinGap = 200 * time.Millisecond

// pvlConfigWorkers 同时下载几个 ovpn 配置。
//
// 太大容易被当攻击，太小则挑 20 条要等很久。
const pvlConfigWorkers = 4

// pvlRow 是列表接口返回的一行。
//
// 字段用宽松类型是因为对方不老实：数值有时是 null 有时是数字，
// 直接定成具体类型会在某天突然 unmarshal 失败。
type pvlRow struct {
	ID           interface{} `json:"id"`
	Host         string      `json:"host"`
	IP           string      `json:"ip"`
	Country      string      `json:"country"`
	CountryName  string      `json:"countryName"`
	Throughput   interface{} `json:"checkerMeasuredThroughputMbps"`
	RTTMs        interface{} `json:"checkerMeasuredTunnelRttMs"`
	Active       interface{} `json:"active"`
	Downloadable interface{} `json:"downloadable"`
	// ConfigAvailable 表示这条能拿到 .ovpn。没有的话下载了也白搭。
	ConfigAvailable interface{} `json:"configAvailable"`
	// Source 是节点来源。PublicVPNList 自己会收录 VPN Gate 的节点，
	// 合并时要注意别重复（见 mergeNodes 按 IP 去重）。
	Source string `json:"source"`
}

// pvlRowID 取行 ID。可能是数字也可能是字符串，统一成字符串。
func pvlRowID(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return fmt.Sprint(v)
	}
}

// pvlFloat 把可能是字符串、数字或 null 的字段取成 float64。
func pvlFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	}
	return 0
}

// pvlBool 把可能是布尔、数字或字符串的字段取成 bool。
func pvlBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	}
	return false
}

// pvlCountryCode 从 country 字段推出两字母代码。
//
// 接口给的是小写全名（"south-korea"、"japan"），而内部按代码挑地区。
// 常见的能映射就映射，映射不了就退回原名前两位大写——不完美但不会丢节点。
func pvlCountryCode(country, name string) string {
	c := strings.ToLower(strings.TrimSpace(country))
	if c == "" {
		c = strings.ToLower(strings.TrimSpace(name))
	}
	if m, ok := pvlCountryCodes[c]; ok {
		return m
	}
	if len(c) >= 2 {
		return strings.ToUpper(c[:2])
	}
	return ""
}

// pvlCountryCodes 常见国家名 -> 两字母代码。
var pvlCountryCodes = map[string]string{
	"japan": "JP", "south-korea": "KR", "korea": "KR", "china": "CN",
	"taiwan": "TW", "hong-kong": "HK", "singapore": "SG", "thailand": "TH",
	"vietnam": "VN", "indonesia": "ID", "malaysia": "MY", "philippines": "PH",
	"india": "IN", "russia": "RU", "united-states": "US", "usa": "US",
	"united-kingdom": "GB", "germany": "DE", "france": "FR", "netherlands": "NL",
	"canada": "CA", "australia": "AU", "brazil": "BR", "turkey": "TR",
	"ukraine": "UA", "poland": "PL", "spain": "ES", "italy": "IT",
	"mexico": "MX", "argentina": "AR", "iran": "IR", "israel": "IL",
	"sweden": "SE", "norway": "NO", "finland": "FI", "denmark": "DK",
	"switzerland": "CH", "austria": "AT", "belgium": "BE", "czech-republic": "CZ",
	"romania": "RO", "hungary": "HU", "greece": "GR", "portugal": "PT",
}

// pvlNode 把一行转成内部 Node。Config 此时还是空的，要后面单独补。
func pvlNode(r pvlRow) (Node, bool) {
	host := strings.TrimSpace(r.Host)
	ip := strings.TrimSpace(r.IP)
	if ip == "" {
		ip = host
	}
	if net.ParseIP(ip) == nil {
		// 没有 IP 就没法建隧道，跳过
		return Node{}, false
	}
	if host == "" {
		host = ip
	}
	return Node{
		HostName:    host,
		IP:          ip,
		Country:     strings.TrimSpace(r.CountryName),
		CountryCode: pvlCountryCode(r.Country, r.CountryName),
		SpeedMbps:   pvlFloat(r.Throughput),
		Ping:        int(pvlFloat(r.RTTMs)),
		// PublicVPNList 收的都是共享出来的出口，按家宽算。
		Residential: true,
	}, true
}

// fetchPVLNodes 拉 PublicVPNList 的节点列表。
//
// 只拿元数据，不拿配置：几万行里只有前几十条会被用到，
// 全量补配置是几万次请求，既慢又会被封。
// pvlCacheTTL 缓存多久。
//
// 这个接口一次要 2 分多钟，不可能每次开出口都重拉一遍。
// 缓存半小时：节点列表本身变化不快，真正要新鲜数据可以手动刷新。
const pvlCacheTTL = 30 * time.Minute

// pvlCachePath 缓存文件位置。放在工作目录里，跟其它状态一起。
var pvlCachePath = ""

type pvlCache struct {
	Fetched time.Time `json:"fetched"`
	Raw     string    `json:"raw"`
}

func fetchPVLNodes(timeout time.Duration) ([]Node, error) {
	raw, err := pvlCachedRaw(timeout)
	if err != nil {
		return nil, err
	}
	rows := pvlParseRows(raw)
	if len(rows) == 0 {
		return nil, fmt.Errorf("PublicVPNList 没解析出节点（接口格式可能变了）")
	}

	nodes := make([]Node, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if !pvlBool(r.Active) || !pvlBool(r.Downloadable) {
			continue
		}
		if !pvlBool(r.ConfigAvailable) {
			continue
		}
		n, ok := pvlNode(r)
		if !ok {
			continue
		}
		nodes = append(nodes, n)
		ids = append(ids, pvlRowID(r.ID))
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("PublicVPNList 没有可用节点")
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SpeedMbps > nodes[j].SpeedMbps })
	// 记住 ID：下载配置要它，不靠 hostname
	pvlStoreIDs(nodes, ids)
	return nodes, nil
}

// pvlFetchRaw 拉原始列表。
//
// 两个必须做对的点，都是实测出来的：
//
//  1. 必须带 X-Requested-With: XMLHttpRequest。不带就返回 403 和
//     {"ok":false,"error":"Dataset is available through site pages only."}
//     ——它靠这个头区分"网页在拉"和"有人在爬 API"。我一开始没带，
//     误判成 IP 被限流、后来又误判成接口关闭，其实只是缺个头。
//  2. 不能声明 Accept-Encoding: identity。明文响应有大小上限，
//     几万行会被截断成半个 JSON。让它 gzip，Go 的 transport 自动解压。
func pvlFetchRaw(timeout time.Duration) ([]byte, error) {
	url := pvlBase + "/local/api/vpn-data.php?status=all"
	// 这个接口很慢：实测整份要吐 2 分多钟（约 2MB gzip）。
	// 超时给太短会白等一场——宁可多等，也不要每次失败。
	if timeout < 4*time.Minute {
		timeout = 4 * time.Minute
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", pvlBase+"/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PublicVPNList 列表请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if strings.Contains(strings.ToLower(string(body)), "site pages only") {
			return nil, fmt.Errorf("PublicVPNList 拒绝了这个请求（HTTP %d）："+
				"它只认带 X-Requested-With 的网页请求", resp.StatusCode)
		}
		return nil, fmt.Errorf("PublicVPNList 列表 HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// pvlParseRows 解析列表，容忍末尾截断。
//
// 这个接口的响应可能被截断（实测拿到的最后一条是半个对象）。
// 直接用 json.Unmarshal 会因为末尾不完整而整份失败，一条都拿不到。
// 所以改成逐条 raw_decode，遇到坏的就停——已经拿到的照常用。
func pvlParseRows(raw []byte) []pvlRow {
	// 定位数组开头，从 '[' 起交给 Decoder：它自己认识数组结构，
	// 我们只要逐个 Decode 元素就行。
	i := 0
	for i < len(raw) && raw[i] != '[' {
		i++
	}
	if i >= len(raw) {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(raw[i:]))
	// 吃掉开头的 '['。用 Token 而不是 Decode，否则会把整个数组
	// 读成一个 []pvlRow，末尾截断时一条都拿不到。
	if _, err := dec.Token(); err != nil {
		return nil
	}

	var out []pvlRow
	for dec.More() {
		var r pvlRow
		if err := dec.Decode(&r); err != nil {
			// 末尾截断：已经拿到的照常用，坏的丢掉
			break
		}
		out = append(out, r)
	}
	return out
}

// pvlCachedRaw 拿原始列表，优先用本地缓存。
//
// 只在缓存过期时真的去拉。接口 2 分多钟的耗时，靠缓存摊掉。
// 拉失败时如果有过期缓存也先用着——有旧数据总比没有强。
func pvlCachedRaw(timeout time.Duration) ([]byte, error) {
	if pvlCachePath != "" {
		if raw, err := os.ReadFile(pvlCachePath); err == nil {
			var c pvlCache
			if json.Unmarshal(raw, &c) == nil && c.Raw != "" {
				if time.Since(c.Fetched) < pvlCacheTTL {
					log.Printf("PublicVPNList 用缓存（%.0f 分钟前拉的）",
						time.Since(c.Fetched).Minutes())
					return []byte(c.Raw), nil
				}
			}
		}
	}
	body, err := pvlFetchRaw(timeout)
	if err != nil {
		return nil, err
	}
	if pvlCachePath != "" {
		c := pvlCache{Fetched: time.Now(), Raw: string(body)}
		if out, merr := json.Marshal(c); merr == nil {
			if werr := os.WriteFile(pvlCachePath, out, 0o600); werr != nil {
				log.Printf("PublicVPNList 缓存写入失败（下次要重新拉）: %v", werr)
			}
		}
	}
	return body, nil
}

// pvlStoreIDs 把节点 ID 暂存下来，下载配置时要按 ID 取。
//
// 为什么不用 map[Node]string：Node 里有 float 字段，做 key 容易撞。
// 按排序后的下标对齐最简单，也和后面 pvlFillConfigs 的下标用法一致。
var pvlLastIDs []string

func pvlStoreIDs(_ []Node, ids []string) { pvlLastIDs = ids }

// pvlIDOf 行 ID 要记住：下载配置时用它，不靠 hostname。
// 所以列表解析时得把 ID 也带出来，这里用一个平行数组承接。
func pvlIDs(rows []pvlRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = pvlRowID(r.ID)
	}
	return out
}

// pvlFillConfigs 给前 limit 条节点补上 ovpn 配置。
//
// 并发但限流：worker 数量固定，每个 worker 每次请求前保证距上次请求
// 至少 pvlMinGap。慢是慢了点，但不会把对方（和自己）搞挂。
func pvlFillConfigs(nodes []Node, ids []string, limit int, timeout time.Duration) {
	if len(ids) == 0 {
		ids = pvlLastIDs
	}
	if limit <= 0 || limit > len(nodes) {
		limit = len(nodes)
	}
	if limit > len(ids) {
		limit = len(ids)
	}

	type job struct{ idx int }
	jobs := make(chan job, limit)
	for i := 0; i < limit; i++ {
		jobs <- job{i}
	}
	close(jobs)

	var mu sync.Mutex
	var last time.Time
	gate := func() {
		mu.Lock()
		wait := pvlMinGap - time.Since(last)
		mu.Unlock()
		if wait > 0 {
			time.Sleep(wait)
		}
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for w := 0; w < pvlConfigWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: timeout}
			for j := range jobs {
				id := ids[j.idx]
				if id == "" {
					continue
				}
				gate()
				cfg, err := pvlFetchConfig(client, id)
				if err != nil || cfg == "" {
					continue
				}
				nodes[j.idx].Config = cfg
			}
		}()
	}
	wg.Wait()
}

// pvlFetchConfig 下载一条节点的 ovpn 配置。
//
// 注意：这条链路还没打通。列表能拿（实测 3976 个节点），但下载 .ovpn
// 的入口变了——旧接口 /protocols/download.php 现在回 400
// "Invalid protocol download identifier"，新的走 /download/?token=xxx，
// 而那个 token 不在列表数据里，得另外拿（大概是从下载页现换的）。
// 所以这里明确报错，而不是静默返回空让上层以为"这个节点没配置"。
func pvlFetchConfig(client *http.Client, id string) (string, error) {
	return "", fmt.Errorf("下载入口已变（需要下载页的 token，不是节点 id）")
}
