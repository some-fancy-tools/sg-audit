package audit

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func TestResult_Print(t *testing.T) {
	type fields struct {
		Permissions   *ec2.IpPermission
		IPRange       *ec2.IpRange
		SeverityLevel SeverityLevel
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "critical",
			fields: fields{
				Permissions: &ec2.IpPermission{
					FromPort:   aws.Int64(1024),
					ToPort:     aws.Int64(1024),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{{
						CidrIp: aws.String("0.0.0.0/0"),
					}},
				},
				IPRange: &ec2.IpRange{
					CidrIp: aws.String("0.0.0.0/0"),
				},
				SeverityLevel: SeverityLevelCritical,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{
				Permissions:   tt.fields.Permissions,
				IPRange:       tt.fields.IPRange,
				SeverityLevel: tt.fields.SeverityLevel,
			}
			r.Print()
		})
	}
}
