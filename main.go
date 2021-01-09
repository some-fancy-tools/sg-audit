package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"git.dcpri.me/some-fancy-tools/sg-audit/audit"
)

var (
	profile = flag.String("profile", "", "AWS Profile to use")
	region  = flag.String("region", "", "AWS Region to use")
)

func main() {
	flag.Parse()
	aws, err := audit.NewAWS(*profile, *region)
	if err != nil {
		log.Fatal(err)
	}
	sgs, err := aws.DescribeSecurityGroups()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Got %d Security Groups, starting audit...\n", len(sgs))
	for i, sg := range sgs {
		time.Sleep(time.Millisecond * 100)

		fmt.Printf("Audited %d Security Groups\r", i)

		rs := audit.Audit(sg)
		for _, r := range rs {
			r.Print()
		}
	}
	fmt.Printf("Audited %d Security Groups\n", len(sgs))
}
