// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/fabric-creed/fabric-sdk-go/test/performance

replace github.com/fabric-creed/fabric-sdk-go/ => ../../

require (
	github.com/fabric-creed/fabric-sdk-go/ v1.0.2-gm // indirect
	github.com/golang/protobuf v1.3.3
	github.com/fabric-creed/fabric-protos-go v0.0.0-20210621061524-cae0a59d99d3
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.5.1
	golang.org/x/net v0.0.0-20190813141303-74dc4d7220e7
	github.com/fabric-creed/grpc v1.29.1-gm
)

go 1.14
