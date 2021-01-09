package main

import (
	"flag"
	"fmt"
	"log"

	"git.dcpri.me/some-fancy-tools/sg-audit/audit"
)

var (
	profile = flag.String("profile", "", "AWS Profile to use")
	region  = flag.String("region", "", "AWS Region to use")
	nocolor = flag.Bool("no-color", false, "No Colored output")
	csv     = flag.Bool("csv", false, "Output in CSV Format")
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
	ins, err := aws.DescribeInstances()
	if err != nil {
		log.Fatal(err)
	}
	sgmap := map[string]int{}
	for _, in := range ins {
		for _, sg := range in.SecurityGroups {
			if _, ok := sgmap[*sg.GroupId]; !ok {
				sgmap[*sg.GroupId] = 0
			}
			sgmap[*sg.GroupId]++
		}
	}
	if *csv {
		fmt.Println(audit.CSVHeader)
	} else {
		fmt.Printf("Got %d Security Groups, starting audit...\n", len(sgs))
	}
	for i, sg := range sgs {
		// time.Sleep(time.Millisecond * 100)
		if !*csv {
			fmt.Printf("Audited %d Security Groups\r", i)
		}
		rs := audit.Audit(sg)
		for _, r := range rs {
			r.InstanceCount = sgmap[r.SecurityGroupID]
			r.AddColor()
			if *csv {
				fmt.Print(r.String(audit.ResultFormatCSV))
			} else if *nocolor {
				fmt.Print(r.String(audit.ResultFormatLog))
			} else {
				fmt.Print(r.String(audit.ResultFormatLogColor))
			}
		}
	}
	if !*csv {
		fmt.Printf("Audited %d Security Groups\n", len(sgs))
	}
}
