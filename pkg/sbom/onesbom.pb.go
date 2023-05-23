// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.19.6
// source: protobuf/onesbom.proto

package sbom

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PersonIdentifier struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Type    string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	Comment string `protobuf:"bytes,3,opt,name=comment,proto3" json:"comment,omitempty"`
}

func (x *PersonIdentifier) Reset() {
	*x = PersonIdentifier{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protobuf_onesbom_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PersonIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PersonIdentifier) ProtoMessage() {}

func (x *PersonIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_protobuf_onesbom_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PersonIdentifier.ProtoReflect.Descriptor instead.
func (*PersonIdentifier) Descriptor() ([]byte, []int) {
	return file_protobuf_onesbom_proto_rawDescGZIP(), []int{0}
}

func (x *PersonIdentifier) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *PersonIdentifier) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *PersonIdentifier) GetComment() string {
	if x != nil {
		return x.Comment
	}
	return ""
}

var File_protobuf_onesbom_proto protoreflect.FileDescriptor

var file_protobuf_onesbom_proto_rawDesc = []byte{
	0x0a, 0x16, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x6f, 0x6e, 0x65, 0x73, 0x62,
	0x6f, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x70, 0x75, 0x65, 0x72, 0x63, 0x6f,
	0x2e, 0x6f, 0x6e, 0x65, 0x73, 0x62, 0x6f, 0x6d, 0x22, 0x50, 0x0a, 0x10, 0x50, 0x65, 0x72, 0x73,
	0x6f, 0x6e, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x42, 0x07, 0x5a, 0x05, 0x73, 0x62,
	0x6f, 0x6d, 0x2f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protobuf_onesbom_proto_rawDescOnce sync.Once
	file_protobuf_onesbom_proto_rawDescData = file_protobuf_onesbom_proto_rawDesc
)

func file_protobuf_onesbom_proto_rawDescGZIP() []byte {
	file_protobuf_onesbom_proto_rawDescOnce.Do(func() {
		file_protobuf_onesbom_proto_rawDescData = protoimpl.X.CompressGZIP(file_protobuf_onesbom_proto_rawDescData)
	})
	return file_protobuf_onesbom_proto_rawDescData
}

var file_protobuf_onesbom_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_protobuf_onesbom_proto_goTypes = []interface{}{
	(*PersonIdentifier)(nil), // 0: puerco.onesbom.PersonIdentifier
}
var file_protobuf_onesbom_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protobuf_onesbom_proto_init() }
func file_protobuf_onesbom_proto_init() {
	if File_protobuf_onesbom_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protobuf_onesbom_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PersonIdentifier); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protobuf_onesbom_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protobuf_onesbom_proto_goTypes,
		DependencyIndexes: file_protobuf_onesbom_proto_depIdxs,
		MessageInfos:      file_protobuf_onesbom_proto_msgTypes,
	}.Build()
	File_protobuf_onesbom_proto = out.File
	file_protobuf_onesbom_proto_rawDesc = nil
	file_protobuf_onesbom_proto_goTypes = nil
	file_protobuf_onesbom_proto_depIdxs = nil
}
