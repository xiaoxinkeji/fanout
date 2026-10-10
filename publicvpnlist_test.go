package main

import (
	"testing"
	"time"
)

// 列表能拉到就说明接口和限流都还正常。
// 这个源是外部站点，被限流了会 403，所以拉不到就跳过而不是判失败。
func TestFetchPVLNodes(t *testing.T) {
	nodes, err := fetchPVLNodes(90 * time.Second)
	if err != nil {
		t.Skipf("PublicVPNList 不可用（外部站点或限流）: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("拉到了但没有节点")
	}
	t.Logf("拿到 %d 个节点，最快的 %.1f Mbps", len(nodes), nodes[0].SpeedMbps)

	// 前几个必须有 IP 和主机名，不然建不了隧道
	for i, n := range nodes {
		if i >= 5 {
			break
		}
		if n.HostName == "" || n.IP == "" {
			t.Errorf("第 %d 个节点缺主机名或 IP: %+v", i, n)
		}
	}
}

// 类型不老实：同一字段有时数字有时字符串，取不出来会静默丢节点。
func TestPVLFieldCoercion(t *testing.T) {
	if got := pvlFloat("123.5"); got != 123.5 {
		t.Errorf("字符串: %v", got)
	}
	if got := pvlFloat(float64(42)); got != 42 {
		t.Errorf("数字: %v", got)
	}
	if got := pvlFloat(nil); got != 0 {
		t.Errorf("nil 应为 0: %v", got)
	}
	for _, s := range []string{"1", "true", "yes", "on"} {
		if !pvlBool(s) {
			t.Errorf("%q 应为真", s)
		}
	}
	if pvlBool("0") || pvlBool("") || pvlBool(nil) {
		t.Error("0/空/nil 应为假")
	}
	if got := pvlRowID(float64(12345)); got != "12345" {
		t.Errorf("数字 ID: %v", got)
	}
	if got := pvlRowID(" ab12 "); got != "ab12" {
		t.Errorf("字符串 ID 应去掉空格: %q", got)
	}
}

// 没有 IP 的节点建不了隧道，必须被过滤掉
func TestPVLNode_SkipsNoIP(t *testing.T) {
	if _, ok := pvlNode(pvlRow{HostName: "h", IP: "not-an-ip"}); ok {
		t.Error("非法 IP 应被跳过")
	}
	n, ok := pvlNode(pvlRow{HostName: "h1", IP: "1.2.3.4"})
	if !ok {
		t.Fatal("合法节点应保留")
	}
	if !n.Residential {
		t.Error("PublicVPNList 的节点按家宽算")
	}
	// 没 hostname 时用 IP 顶上
	n2, _ := pvlNode(pvlRow{IP: "5.6.7.8"})
	if n2.HostName != "5.6.7.8" {
		t.Errorf("缺主机名应拿 IP 顶: %q", n2.HostName)
	}
}

// 合并去重：两个源可能有同一个 IP
func TestMergeNodes_DedupByIP(t *testing.T) {
	a := []Node{{IP: "1.1.1.1", HostName: "a", SpeedMbps: 10}}
	b := []Node{{IP: "1.1.1.1", HostName: "dup"}, {IP: "2.2.2.2", HostName: "b", SpeedMbps: 50}}
	out := mergeNodes(a, b)
	if len(out) != 2 {
		t.Fatalf("去重后应剩 2 个，得到 %d", len(out))
	}
	// 快的排前面
	if out[0].IP != "2.2.2.2" {
		t.Errorf("应按速度排序，第一个是 %s", out[0].IP)
	}
}

func TestNodeSource_Default(t *testing.T) {
	// 没配过时必须是 vpngate，不能因为加了新源就改掉老用户的行为
	if got := nodeSource(); got != "vpngate" {
		t.Errorf("默认应为 vpngate，得到 %q", got)
	}
}
