package audit

import (
	"os"

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

// Audit for auditing the security group
func Audit(sg *ec2.SecurityGroup) []Result {
	rs := []Result{}
	for _, r := range sg.IpPermissions {
		for _, ip := range r.IpRanges {
			if r.FromPort == nil && r.ToPort == nil {
				r.FromPort = aws.Int64(0)
				r.ToPort = aws.Int64(65535)
			}
			// TCP/UDP Open ports other than 80/443 to the internet
			if openToInternet(ip, r.IpProtocol, r.FromPort, r.ToPort) {
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPRange:         ip,
					SeverityLevel:   SeverityLevelCritical,
				})
			}
			if allOpenToIP(ip, r.IpProtocol, r.FromPort, r.ToPort) {
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPRange:         ip,
					SeverityLevel:   SeverityLevelWarning,
				})
			}

		}
		for _, ipv6 := range r.Ipv6Ranges {
			if openToInternetv6(ipv6, r.IpProtocol, r.FromPort, r.ToPort) {
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPv6Range:       ipv6,
					SeverityLevel:   SeverityLevelCritical,
				})
			}
			if allOpenToIPv6(ipv6, r.IpProtocol, r.FromPort, r.ToPort) {
				rs = append(rs, Result{
					SecurityGroupID: *sg.GroupId,
					Permissions:     r,
					IPv6Range:       ipv6,
					SeverityLevel:   SeverityLevelWarning,
				})
			}
		}
	}
	return rs
}
