package audit

import (
	"fmt"
	"testing"
)

func TestDescribeSecurityGroups(t *testing.T) {
	a, _ := NewAWS("", "")
	g, err := a.DescribeSecurityGroups()
	if err != nil {
		t.Logf("DescribeSecurityGroups() = %v", err)
	}
	fmt.Println(len(g))

	fmt.Println(g[0].IpPermissions)
}
