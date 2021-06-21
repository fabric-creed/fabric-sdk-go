// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/fabric-creed/fabric-sdk-go/test/integration

replace github.com/fabric-creed/fabric-sdk-go/ => ../../

require (
	github.com/golang/protobuf v1.3.3
	github.com/hyperledger/fabric-config v0.0.5
	github.com/fabric-creed/fabric-protos-go v0.0.0-20210621061524-cae0a59d99d3
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.5.1
	github.com/fabric-creed/grpc v1.29.1-gm
)

go 1.14
