package audit

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/fatih/color"
)

const (
	// SeverityLevelWarning can be ok
	SeverityLevelWarning SeverityLevel = iota
	// SeverityLevelCritical can be disasterous
	SeverityLevelCritical
)

var (
	levels = []string{
		"WARN", "CRIT", "SKIP",
	}
)

// SeverityLevel type
type SeverityLevel int

// Result type to structure the log output
type Result struct {
	SecurityGroupID string
	Permissions     *ec2.IpPermission
	IPRange         *ec2.IpRange
	IPv6Range       *ec2.Ipv6Range
	SeverityLevel   SeverityLevel
	InstanceCount   int
}

func (r *Result) String() string {
	return "to be implemented"
}

// Print for printing out the logs in color form.
func (r *Result) Print() {
	defer color.Unset()
	if r.SeverityLevel == SeverityLevelCritical {
		color.Set(color.FgRed)
	}
	if r.SeverityLevel == SeverityLevelWarning {
		color.Set(color.FgYellow)
	}
	var portRange string
	if *r.Permissions.FromPort == -1 && *r.Permissions.ToPort == -1 {
		portRange = fmt.Sprintf("all")
	} else if *r.Permissions.FromPort == *r.Permissions.ToPort {
		portRange = fmt.Sprintf("%d", *r.Permissions.FromPort)
	} else {
		portRange = fmt.Sprintf("%d-%d", *r.Permissions.FromPort, *r.Permissions.ToPort)
	}
	if r.Permissions.IpRanges != nil && r.IPRange != nil {
		for _, ip := range r.Permissions.IpRanges {
			if *ip.CidrIp == *r.IPRange.CidrIp {
				if ip.Description == nil {
					ip.Description = aws.String("-")
				}
				if strings.Contains(*ip.Description, "sgaudit:skip") {
					color.Set(color.FgCyan)
				}
				if strings.Contains(*ip.Description, "sgaudit:checked") {
					color.Set(color.FgGreen)
				}
				fmt.Printf("[%s] [%4d] [%-20s] %s/%s <- %s [%s]\n", levels[r.SeverityLevel], r.InstanceCount,
					r.SecurityGroupID, portRange, *r.Permissions.IpProtocol,
					*ip.CidrIp, *ip.Description)
			}
		}
	}
	if r.Permissions.Ipv6Ranges != nil && r.IPv6Range != nil {
		for _, ipv6 := range r.Permissions.Ipv6Ranges {
			if *ipv6.CidrIpv6 == *r.IPv6Range.CidrIpv6 {
				if ipv6.Description == nil {
					ipv6.Description = aws.String("-")
				}
				if strings.Contains(*ipv6.Description, "sgaudit:skip") {
					color.Set(color.FgCyan)
				}
				if strings.Contains(*ipv6.Description, "sgaudit:checked") {
					color.Set(color.FgGreen)
				}
				fmt.Printf("[%s] [%4d] [%-20s] %s/%s <- %s [%s]\n", levels[r.SeverityLevel], r.InstanceCount,
					r.SecurityGroupID, portRange, *r.Permissions.IpProtocol,
					*ipv6.CidrIpv6, *ipv6.Description)
			}
		}
	}
}
