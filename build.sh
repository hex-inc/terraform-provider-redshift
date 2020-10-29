#!/bin/bash

env GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -o ./dist/darwin/amd64/terraform-provider-redshift_hex github.com/frankfarrell/terraform-provider-redshift
env GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o ./dist/linux/amd64/terraform-provider-redshift_hex github.com/frankfarrell/terraform-provider-redshift
