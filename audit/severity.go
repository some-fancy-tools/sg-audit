package audit

import (
	"encoding/csv"
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

const (
	// ResultFormatCSV for CSV Formatted String
	ResultFormatCSV ResultFormat = iota
	// ResultFormatLog for Log Formatted String
	ResultFormatLog
	// ResultFormatLogColor for Log Formatted String with Color
	ResultFormatLogColor
)

var (
	levels = []string{
		"WARN", "CRIT", "SKIP",
	}

	// CSVHeader with columns
	CSVHeader = strings.Join([]string{"Level", "Instance Count", "Group ID", "Port Range", "Protocol", "IP CIDR", "Description"}, ",")
)

// SeverityLevel type
type SeverityLevel int

// ResultFormat for formatting result type
type ResultFormat int

// Result type to structure the log output
type Result struct {
	SecurityGroupID string
	Permissions     *ec2.IpPermission
	IPRange         *ec2.IpRange
	IPv6Range       *ec2.Ipv6Range
	SeverityLevel   SeverityLevel
	InstanceCount   int
	Color           *color.Color
	PortRange       string
}

// AddColor to update the color
func (r *Result) AddColor() {
	if r.SeverityLevel == SeverityLevelCritical {
		r.Color = color.New(color.FgRed)
	}
	if r.SeverityLevel == SeverityLevelWarning {
		r.Color = color.New(color.FgYellow)
	}
	if r.InstanceCount > 0 {
		r.Color = r.Color.Add(color.Bold)
	}
	if *r.Permissions.FromPort == -1 && *r.Permissions.ToPort == -1 {
		r.PortRange = fmt.Sprintf("all")
	} else if *r.Permissions.FromPort == *r.Permissions.ToPort {
		r.PortRange = fmt.Sprintf("%d", *r.Permissions.FromPort)
	} else {
		r.PortRange = fmt.Sprintf("%d-%d", *r.Permissions.FromPort, *r.Permissions.ToPort)
	}
	if r.Permissions.IpRanges != nil && r.IPRange != nil {
		for _, ip := range r.Permissions.IpRanges {
			if *ip.CidrIp == *r.IPRange.CidrIp {
				if ip.Description == nil {
					ip.Description = aws.String("-")
				}
				if strings.Contains(*ip.Description, "sgaudit:skip") {
					r.Color = r.Color.Add(color.FgCyan)
				}
				if strings.Contains(*ip.Description, "sgaudit:checked") {
					r.Color = r.Color.Add(color.FgGreen)
				}
			}
		}
	}
	if r.Permissions.Ipv6Ranges != nil && r.IPv6Range != nil {
		for _, ipv6 := range r.Permissions.Ipv6Ranges {
			if *ipv6.CidrIpv6 == *r.IPv6Range.CidrIpv6 {
				if ipv6.Description == nil {
					ipv6.Description = aws.String("-")
				}
				if ipv6.Description != nil && strings.Contains(*ipv6.Description, "sgaudit:skip") {
					r.Color = r.Color.Add(color.FgCyan)
				}
				if strings.Contains(*ipv6.Description, "sgaudit:checked") {
					r.Color = r.Color.Add(color.FgGreen)
				}
			}
		}
	}
}

func (r *Result) String(rf ResultFormat) string {
	sb := strings.Builder{}
	segments := [][]interface{}{}
	var cw *csv.Writer
	if rf == ResultFormatCSV {
		cw = csv.NewWriter(&sb)
	}
	if rf == ResultFormatLogColor {
		r.AddColor()
	}
	for _, ip := range r.Permissions.IpRanges {
		if r.IPRange == nil || r.IPRange.CidrIp == nil {
			continue
		}
		if *r.IPRange.CidrIp != *ip.CidrIp {
			continue
		}
		if ip.Description == nil {
			ip.Description = aws.String("-")
		}
		segments = append(segments, []interface{}{levels[r.SeverityLevel], r.InstanceCount,
			r.SecurityGroupID, r.PortRange, *r.Permissions.IpProtocol,
			*ip.CidrIp, *ip.Description})
	}
	for _, ip := range r.Permissions.Ipv6Ranges {
		if r.IPv6Range == nil || r.IPv6Range.CidrIpv6 == nil {
			continue
		}
		if *r.IPv6Range.CidrIpv6 != *ip.CidrIpv6 {
			continue
		}
		if ip.Description == nil {
			ip.Description = aws.String("-")
		}
		segments = append(segments, []interface{}{levels[r.SeverityLevel], r.InstanceCount,
			r.SecurityGroupID, r.PortRange, *r.Permissions.IpProtocol,
			*ip.CidrIpv6, *ip.Description})
	}
	for _, segment := range segments {
		switch rf {
		case ResultFormatLogColor:
			sb.WriteString(r.Color.Sprintf("[%s] [%4d] [%-20s] %s/%s <- %s [%s]\n", segment...))
		case ResultFormatLog:
			sb.WriteString(fmt.Sprintf("[%s] [%4d] [%-20s] %s/%s <- %s [%s]\n", segment...))
		case ResultFormatCSV:
			cw.Write([]string{levels[r.SeverityLevel], fmt.Sprint(r.InstanceCount),
				r.SecurityGroupID, r.PortRange, *r.Permissions.IpProtocol,
				fmt.Sprint(segment[5]), fmt.Sprint(segment[6])})
		}
	}
	if cw != nil {
		cw.Flush()
	}
	return sb.String()
}

// Print for printing out the logs in color form.
func (r *Result) Print(format ResultFormat) {
	fmt.Print(r.String(format))
}
