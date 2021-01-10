package audit

import (
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// AWS Related Services
type AWS struct {
	profile string
	region  string
	ec2svc  *ec2.EC2
}

// NewAWS for a new AWS variable with EC2 Service initialized
func NewAWS(profile, region string) (*AWS, error) {
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}
	if profile == "" {
		profile = "default"
	}
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String(region),
		},
		Profile: profile,
	})
	if err != nil {
		return nil, err
	}
	return &AWS{
		profile: profile,
		region:  region,
		ec2svc:  ec2.New(sess),
	}, nil
}

// DescribeSecurityGroups to call DescribeSecurityGroups API
func (a *AWS) DescribeSecurityGroups() ([]*ec2.SecurityGroup, error) {
	g := []*ec2.SecurityGroup{}
	next := aws.String("")
	for next != nil {
		o, err := a.ec2svc.DescribeSecurityGroups(
			&ec2.DescribeSecurityGroupsInput{
				NextToken: next,
			},
		)
		if err != nil {
			return nil, err
		}
		next = o.NextToken
		g = append(g, o.SecurityGroups...)
	}
	return g, nil
}

// DescribeInstances to call DescribeInstances API
func (a *AWS) DescribeInstances() ([]*ec2.Instance, error) {
	ins := []*ec2.Instance{}
	next := aws.String("")
	for next != nil {
		o, err := a.ec2svc.DescribeInstances(
			&ec2.DescribeInstancesInput{
				NextToken: next,
			},
		)
		if err != nil {
			return nil, err
		}
		next = o.NextToken
		for _, r := range o.Reservations {
			ins = append(ins, r.Instances...)
		}
	}
	return ins, nil
}

// Audit for auditing the security group
func Audit(sg *ec2.SecurityGroup) []Result {
	rs := []Result{}
	for _, r := range sg.IpPermissions {
		var severity SeverityLevel
		for _, ip := range r.IpRanges {
			if r.FromPort == nil && r.ToPort == nil {
				r.FromPort = aws.Int64(0)
				r.ToPort = aws.Int64(65535)
			}
			if ip.Description == nil {
				ip.Description = aws.String("-")
			}
			if strings.Contains(*ip.Description, "sgaudit:skip") {
				severity = SeverityLevelSkip
			}
			if strings.Contains(*ip.Description, "sgaudit:checked") {
				severity = SeverityLevelChecked
			}
			// TCP/UDP Open ports other than 80/443 to the internet
			if openToInternet(ip, r.IpProtocol, r.FromPort, r.ToPort) {
				if severity == SeverityLevelNone {
					severity = SeverityLevelCritical
				}
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPRange:         ip,
					SeverityLevel:   severity,
				})
				continue
			}
			if allOpenToIP(ip, r.IpProtocol, r.FromPort, r.ToPort) {
				if severity == SeverityLevelNone {
					severity = SeverityLevelWarning
				}
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPRange:         ip,
					SeverityLevel:   severity,
				})
			}
		}
		for _, ipv6 := range r.Ipv6Ranges {
			if ipv6.Description == nil {
				ipv6.Description = aws.String("-")
			}
			if strings.Contains(*ipv6.Description, "sgaudit:skip") {
				severity = SeverityLevelSkip
			}
			if strings.Contains(*ipv6.Description, "sgaudit:checked") {
				severity = SeverityLevelChecked
			}
			if openToInternetv6(ipv6, r.IpProtocol, r.FromPort, r.ToPort) {
				if severity == SeverityLevelNone {
					severity = SeverityLevelCritical
				}
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPv6Range:       ipv6,
					SeverityLevel:   severity,
				})
				continue
			}
			if allOpenToIPv6(ipv6, r.IpProtocol, r.FromPort, r.ToPort) {
				if severity == SeverityLevelNone {
					severity = SeverityLevelWarning
				}
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPv6Range:       ipv6,
					SeverityLevel:   severity,
				})
			}
		}
	}
	return rs
}
