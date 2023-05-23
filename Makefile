# protoc = 0.15.1

.PHONY: proto
proto: ## Compile protobuf and generate go libraries
        protoc --go_out=pkg protobuf/onesbom.proto
