package audit

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func openToInternet(ip *ec2.IpRange, proto *string, fromPort, toPort *int64) bool {
	if *proto == "-1" { // in case of all traffic (won't be used here)
		*proto = "all"
	}

	if *fromPort == *toPort && (*fromPort == 80 || *fromPort == 443) {
		return false
	}

	if *ip.CidrIp == "0.0.0.0/0" {
		return true
	}
	return false
}

func openToInternetv6(ip *ec2.Ipv6Range, proto *string, fromPort, toPort *int64) bool {
	if *proto == "-1" { // in case of all traffic (won't be used here)
		proto = aws.String("tcp-udp")
	}

	if *fromPort == *toPort && (*fromPort == 80 || *fromPort == 443) {
		return false
	}

	if *ip.CidrIpv6 == "::/0" {
		return true
	}
	return false
}

func allOpenToIP(ip *ec2.IpRange, proto *string, fromPort, toPort *int64) bool {
	if *proto != "tcp" && *proto != "udp" {
		return false
	}
	if *fromPort == -1 && *toPort == -1 {
		*fromPort = 0
		*toPort = 65535
	}
	if *fromPort == 0 && *toPort == 65535 {
		return true
	}
	return false
}

func allOpenToIPv6(ipv6 *ec2.Ipv6Range, proto *string, fromPort, toPort *int64) bool {
	if *proto != "tcp" && *proto != "udp" {
		return false
	}
	if *fromPort == -1 && *toPort == -1 {
		*fromPort = 0
		*toPort = 65535
	}
	if *fromPort == 0 && *toPort == 65535 {
		return true
	}
	return false
}
