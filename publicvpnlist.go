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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
// 字段用 interface{} 是因为对方的类型不老实：port 有时是数字有时是字符串，
// 直接定成 int 会在某天突然 unmarshal 失败。
type pvlRow struct {
	ID           interface{} `json:"id"`
	HostName     string      `json:"hostname"`
	IP           string      `json:"ip"`
	Country      string      `json:"country"`
	CountryCode  string      `json:"country_code"`
	Throughput   interface{} `json:"throughput"`
	Active       interface{} `json:"active"`
	Downloadable interface{} `json:"downloadable"`
}

// pvlRowID 取行 ID。它可能是数字也可能是十六进制字符串，统一成字符串。
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

// pvlFloat 把可能是字符串或数字的字段取成 float64。
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

// pvlNode 把一行转成内部 Node。Config 此时还是空的，要后面单独补。
func pvlNode(r pvlRow) (Node, bool) {
	host := strings.TrimSpace(r.HostName)
	ip := strings.TrimSpace(r.IP)
	if host == "" && ip == "" {
		return Node{}, false
	}
	if host == "" {
		host = ip
	}
	if net.ParseIP(ip) == nil {
		// 没有 IP 就没法建隧道，跳过
		return Node{}, false
	}
	return Node{
		HostName:    host,
		IP:          ip,
		Country:     strings.TrimSpace(r.Country),
		CountryCode: strings.ToUpper(strings.TrimSpace(r.CountryCode)),
		SpeedMbps:   pvlFloat(r.Throughput),
		// PublicVPNList 收的都是志愿者共享出来的出口，按家宽算。
		// 它的列表里没有"自营机房"这个区分，VPN Gate 才有。
		Residential: true,
	}, true
}

// fetchPVLNodes 拉 PublicVPNList 的节点列表。
//
// 只拿元数据，不拿配置：几万行里只有前几十条会被用到，
// 全量补配置是几万次请求，既慢又会被封。
func fetchPVLNodes(timeout time.Duration) ([]Node, error) {
	url := pvlBase + "/local/api/vpn-data.php?status=all"
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// 关键：不声明 identity 时对方返回 gzip，Go 的 transport 会自己解压，
	// 但几万行的响应体在解压前就可能被截断。显式要明文最稳。
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "fanout")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PublicVPNList 列表请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 有两种可能：这个 IP 被限流，或者接口整个关了。
		// 后者的响应体是 {"ok":false,"error":"Dataset is available through
		// site pages only."}，看一眼就能区分，别把两者都报成限流。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if strings.Contains(strings.ToLower(string(body)), "site pages only") {
			return nil, fmt.Errorf("PublicVPNList 的 API 已关闭，只能走网页（HTTP %d）", resp.StatusCode)
		}
		return nil, fmt.Errorf("PublicVPNList 列表 HTTP %d（可能是对这个 IP 限流了）", resp.StatusCode)
	}

	var rows []pvlRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("PublicVPNList 列表解析失败: %w", err)
	}

	nodes := make([]Node, 0, len(rows))
	for _, r := range rows {
		if !pvlBool(r.Active) || !pvlBool(r.Downloadable) {
			continue
		}
		if n, ok := pvlNode(r); ok {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("PublicVPNList 没返回可用节点")
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SpeedMbps > nodes[j].SpeedMbps })
	return nodes, nil
}

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
func pvlFetchConfig(client *http.Client, id string) (string, error) {
	url := fmt.Sprintf("%s/protocols/download.php?protocol=openvpn&id=%s&format=json",
		pvlBase, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "fanout")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		ConfigURI string `json:"config_uri"`
		Config    string `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	// 两种字段都接：不同时期接口返回的不一样
	if out.Config != "" {
		return out.Config, nil
	}
	return out.ConfigURI, nil
}
