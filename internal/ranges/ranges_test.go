package ranges

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func build(t *testing.T, spec ...string) string {
	t.Helper()
	var es []Entry[string]
	for _, s := range spec {
		p, v, _ := strings.Cut(s, "=")
		es = append(es, Entry[string]{netip.MustParsePrefix(p), v})
	}
	var parts []string
	for _, r := range Build(es) {
		parts = append(parts, fmt.Sprintf("%s-%s=%s", r.From, r.To, r.Value))
	}
	return strings.Join(parts, " ")
}

func TestBuild(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"10.0.0.0/8=a"}, "10.0.0.0-10.255.255.255=a"},
		// nested: specific wins, outer continues on both sides
		{[]string{"10.0.0.0/8=a", "10.1.0.0/16=b"},
			"10.0.0.0-10.0.255.255=a 10.1.0.0-10.1.255.255=b 10.2.0.0-10.255.255.255=a"},
		// input order does not matter
		{[]string{"10.1.0.0/16=b", "10.0.0.0/8=a"},
			"10.0.0.0-10.0.255.255=a 10.1.0.0-10.1.255.255=b 10.2.0.0-10.255.255.255=a"},
		// nested at the start and end of the outer prefix
		{[]string{"10.0.0.0/8=a", "10.0.0.0/16=b", "10.255.0.0/16=c"},
			"10.0.0.0-10.0.255.255=b 10.1.0.0-10.254.255.255=a 10.255.0.0-10.255.255.255=c"},
		// adjacent equal values merge, differing ones stay apart
		{[]string{"10.0.0.0/25=a", "10.0.0.128/25=a", "10.0.1.0/24=b"},
			"10.0.0.0-10.0.0.255=a 10.0.1.0-10.0.1.255=b"},
		// nested with the same value collapses
		{[]string{"10.0.0.0/8=a", "10.1.0.0/16=a"}, "10.0.0.0-10.255.255.255=a"},
		// three levels
		{[]string{"10.0.0.0/8=a", "10.1.0.0/16=b", "10.1.1.0/24=c"},
			"10.0.0.0-10.0.255.255=a 10.1.0.0-10.1.0.255=b 10.1.1.0-10.1.1.255=c 10.1.2.0-10.1.255.255=b 10.2.0.0-10.255.255.255=a"},
		// end of the address space
		{[]string{"0.0.0.0/0=a", "255.255.255.255/32=b"},
			"0.0.0.0-255.255.255.254=a 255.255.255.255-255.255.255.255=b"},
		{[]string{"0.0.0.0/0=a", "0.0.0.0/32=b"},
			"0.0.0.0-0.0.0.0=b 0.0.0.1-255.255.255.255=a"},
		{[]string{"fc00::/7=a", "fe80::/10=b"}, "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff=a fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff=b"},
		{[]string{"::/0=a", "ffff::/16=b"}, "::-fffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff=a ffff::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff=b"},
	}
	for _, tc := range cases {
		if got := build(t, tc.in...); got != tc.want {
			t.Errorf("%v:\n got  %s\n want %s", tc.in, got, tc.want)
		}
	}
}
