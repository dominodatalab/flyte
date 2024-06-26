// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: flyteidl/plugins/kubeflow/mpi.proto

package kubeflow

import (
	core "github.com/flyteorg/flyte/flyteidl/gen/pb-go/flyteidl/core"
	plugins "github.com/flyteorg/flyte/flyteidl/gen/pb-go/flyteidl/plugins"
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

// Proto for plugin that enables distributed training using https://github.com/kubeflow/mpi-operator
type DistributedMPITrainingTask struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Worker replicas spec
	WorkerReplicas *DistributedMPITrainingReplicaSpec `protobuf:"bytes,1,opt,name=worker_replicas,json=workerReplicas,proto3" json:"worker_replicas,omitempty"`
	// Master replicas spec
	LauncherReplicas *DistributedMPITrainingReplicaSpec `protobuf:"bytes,2,opt,name=launcher_replicas,json=launcherReplicas,proto3" json:"launcher_replicas,omitempty"`
	// RunPolicy encapsulates various runtime policies of the distributed training
	// job, for example how to clean up resources and how long the job can stay
	// active.
	RunPolicy *RunPolicy `protobuf:"bytes,3,opt,name=run_policy,json=runPolicy,proto3" json:"run_policy,omitempty"`
	// Number of slots per worker
	Slots int32 `protobuf:"varint,4,opt,name=slots,proto3" json:"slots,omitempty"`
}

func (x *DistributedMPITrainingTask) Reset() {
	*x = DistributedMPITrainingTask{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DistributedMPITrainingTask) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DistributedMPITrainingTask) ProtoMessage() {}

func (x *DistributedMPITrainingTask) ProtoReflect() protoreflect.Message {
	mi := &file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DistributedMPITrainingTask.ProtoReflect.Descriptor instead.
func (*DistributedMPITrainingTask) Descriptor() ([]byte, []int) {
	return file_flyteidl_plugins_kubeflow_mpi_proto_rawDescGZIP(), []int{0}
}

func (x *DistributedMPITrainingTask) GetWorkerReplicas() *DistributedMPITrainingReplicaSpec {
	if x != nil {
		return x.WorkerReplicas
	}
	return nil
}

func (x *DistributedMPITrainingTask) GetLauncherReplicas() *DistributedMPITrainingReplicaSpec {
	if x != nil {
		return x.LauncherReplicas
	}
	return nil
}

func (x *DistributedMPITrainingTask) GetRunPolicy() *RunPolicy {
	if x != nil {
		return x.RunPolicy
	}
	return nil
}

func (x *DistributedMPITrainingTask) GetSlots() int32 {
	if x != nil {
		return x.Slots
	}
	return 0
}

// Replica specification for distributed MPI training
type DistributedMPITrainingReplicaSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 1~4 deprecated. Use common instead.
	// Number of replicas
	//
	// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
	Replicas int32 `protobuf:"varint,1,opt,name=replicas,proto3" json:"replicas,omitempty"`
	// Image used for the replica group
	//
	// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
	Image string `protobuf:"bytes,2,opt,name=image,proto3" json:"image,omitempty"`
	// Resources required for the replica group
	//
	// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
	Resources *core.Resources `protobuf:"bytes,3,opt,name=resources,proto3" json:"resources,omitempty"`
	// Restart policy determines whether pods will be restarted when they exit
	//
	// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
	RestartPolicy plugins.RestartPolicy `protobuf:"varint,4,opt,name=restart_policy,json=restartPolicy,proto3,enum=flyteidl.plugins.RestartPolicy" json:"restart_policy,omitempty"`
	// MPI sometimes requires different command set for different replica groups
	Command []string `protobuf:"bytes,5,rep,name=command,proto3" json:"command,omitempty"`
	// The common replica spec
	Common *plugins.CommonReplicaSpec `protobuf:"bytes,6,opt,name=common,proto3" json:"common,omitempty"`
}

func (x *DistributedMPITrainingReplicaSpec) Reset() {
	*x = DistributedMPITrainingReplicaSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DistributedMPITrainingReplicaSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DistributedMPITrainingReplicaSpec) ProtoMessage() {}

func (x *DistributedMPITrainingReplicaSpec) ProtoReflect() protoreflect.Message {
	mi := &file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DistributedMPITrainingReplicaSpec.ProtoReflect.Descriptor instead.
func (*DistributedMPITrainingReplicaSpec) Descriptor() ([]byte, []int) {
	return file_flyteidl_plugins_kubeflow_mpi_proto_rawDescGZIP(), []int{1}
}

// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
func (x *DistributedMPITrainingReplicaSpec) GetReplicas() int32 {
	if x != nil {
		return x.Replicas
	}
	return 0
}

// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
func (x *DistributedMPITrainingReplicaSpec) GetImage() string {
	if x != nil {
		return x.Image
	}
	return ""
}

// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
func (x *DistributedMPITrainingReplicaSpec) GetResources() *core.Resources {
	if x != nil {
		return x.Resources
	}
	return nil
}

// Deprecated: Marked as deprecated in flyteidl/plugins/kubeflow/mpi.proto.
func (x *DistributedMPITrainingReplicaSpec) GetRestartPolicy() plugins.RestartPolicy {
	if x != nil {
		return x.RestartPolicy
	}
	return plugins.RestartPolicy(0)
}

func (x *DistributedMPITrainingReplicaSpec) GetCommand() []string {
	if x != nil {
		return x.Command
	}
	return nil
}

func (x *DistributedMPITrainingReplicaSpec) GetCommon() *plugins.CommonReplicaSpec {
	if x != nil {
		return x.Common
	}
	return nil
}

var File_flyteidl_plugins_kubeflow_mpi_proto protoreflect.FileDescriptor

var file_flyteidl_plugins_kubeflow_mpi_proto_rawDesc = []byte{
	0x0a, 0x23, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69,
	0x6e, 0x73, 0x2f, 0x6b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0x2f, 0x6d, 0x70, 0x69, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x19, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e,
	0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x6b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77,
	0x1a, 0x19, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f,
	0x74, 0x61, 0x73, 0x6b, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x26, 0x66, 0x6c, 0x79,
	0x74, 0x65, 0x69, 0x64, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2f, 0x6b, 0x75,
	0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xc9, 0x02, 0x0a, 0x1a, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x64, 0x4d, 0x50, 0x49, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x54, 0x61,
	0x73, 0x6b, 0x12, 0x65, 0x0a, 0x0f, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x72, 0x65, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3c, 0x2e, 0x66, 0x6c,
	0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x6b,
	0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x64, 0x4d, 0x50, 0x49, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x52, 0x65,
	0x70, 0x6c, 0x69, 0x63, 0x61, 0x53, 0x70, 0x65, 0x63, 0x52, 0x0e, 0x77, 0x6f, 0x72, 0x6b, 0x65,
	0x72, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x73, 0x12, 0x69, 0x0a, 0x11, 0x6c, 0x61, 0x75,
	0x6e, 0x63, 0x68, 0x65, 0x72, 0x5f, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x73, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x3c, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e,
	0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x6b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77,
	0x2e, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x64, 0x4d, 0x50, 0x49, 0x54,
	0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x53, 0x70,
	0x65, 0x63, 0x52, 0x10, 0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x65, 0x72, 0x52, 0x65, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x73, 0x12, 0x43, 0x0a, 0x0a, 0x72, 0x75, 0x6e, 0x5f, 0x70, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65,
	0x69, 0x64, 0x6c, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x6b, 0x75, 0x62, 0x65,
	0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x52, 0x75, 0x6e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x09,
	0x72, 0x75, 0x6e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x6c, 0x6f,
	0x74, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x73, 0x6c, 0x6f, 0x74, 0x73, 0x22,
	0xbc, 0x02, 0x0a, 0x21, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x64, 0x4d,
	0x50, 0x49, 0x54, 0x72, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63,
	0x61, 0x53, 0x70, 0x65, 0x63, 0x12, 0x1e, 0x0a, 0x08, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x42, 0x02, 0x18, 0x01, 0x52, 0x08, 0x72, 0x65, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x73, 0x12, 0x18, 0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01, 0x52, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12,
	0x3a, 0x0a, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x18, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x42, 0x02, 0x18, 0x01,
	0x52, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x4a, 0x0a, 0x0e, 0x72,
	0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x1f, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e, 0x70,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x42, 0x02, 0x18, 0x01, 0x52, 0x0d, 0x72, 0x65, 0x73, 0x74, 0x61, 0x72,
	0x74, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
	0x6e, 0x64, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x12, 0x3b, 0x0a, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x23, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x73, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x53, 0x70, 0x65, 0x63, 0x52, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x42, 0xf7,
	0x01, 0x0a, 0x1d, 0x63, 0x6f, 0x6d, 0x2e, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e,
	0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x6b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77,
	0x42, 0x08, 0x4d, 0x70, 0x69, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x46, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x6f, 0x72,
	0x67, 0x2f, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x2f, 0x66, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c,
	0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x62, 0x2d, 0x67, 0x6f, 0x2f, 0x66, 0x6c, 0x79, 0x74, 0x65,
	0x69, 0x64, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2f, 0x6b, 0x75, 0x62, 0x65,
	0x66, 0x6c, 0x6f, 0x77, 0xa2, 0x02, 0x03, 0x46, 0x50, 0x4b, 0xaa, 0x02, 0x19, 0x46, 0x6c, 0x79,
	0x74, 0x65, 0x69, 0x64, 0x6c, 0x2e, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x4b, 0x75,
	0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0xca, 0x02, 0x19, 0x46, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64,
	0x6c, 0x5c, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x5c, 0x4b, 0x75, 0x62, 0x65, 0x66, 0x6c,
	0x6f, 0x77, 0xe2, 0x02, 0x25, 0x46, 0x6c, 0x79, 0x74, 0x65, 0x69, 0x64, 0x6c, 0x5c, 0x50, 0x6c,
	0x75, 0x67, 0x69, 0x6e, 0x73, 0x5c, 0x4b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0x5c, 0x47,
	0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1b, 0x46, 0x6c, 0x79,
	0x74, 0x65, 0x69, 0x64, 0x6c, 0x3a, 0x3a, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x3a, 0x3a,
	0x4b, 0x75, 0x62, 0x65, 0x66, 0x6c, 0x6f, 0x77, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_flyteidl_plugins_kubeflow_mpi_proto_rawDescOnce sync.Once
	file_flyteidl_plugins_kubeflow_mpi_proto_rawDescData = file_flyteidl_plugins_kubeflow_mpi_proto_rawDesc
)

func file_flyteidl_plugins_kubeflow_mpi_proto_rawDescGZIP() []byte {
	file_flyteidl_plugins_kubeflow_mpi_proto_rawDescOnce.Do(func() {
		file_flyteidl_plugins_kubeflow_mpi_proto_rawDescData = protoimpl.X.CompressGZIP(file_flyteidl_plugins_kubeflow_mpi_proto_rawDescData)
	})
	return file_flyteidl_plugins_kubeflow_mpi_proto_rawDescData
}

var file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_flyteidl_plugins_kubeflow_mpi_proto_goTypes = []interface{}{
	(*DistributedMPITrainingTask)(nil),        // 0: flyteidl.plugins.kubeflow.DistributedMPITrainingTask
	(*DistributedMPITrainingReplicaSpec)(nil), // 1: flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec
	(*RunPolicy)(nil),                         // 2: flyteidl.plugins.kubeflow.RunPolicy
	(*core.Resources)(nil),                    // 3: flyteidl.core.Resources
	(plugins.RestartPolicy)(0),                // 4: flyteidl.plugins.RestartPolicy
	(*plugins.CommonReplicaSpec)(nil),         // 5: flyteidl.plugins.CommonReplicaSpec
}
var file_flyteidl_plugins_kubeflow_mpi_proto_depIdxs = []int32{
	1, // 0: flyteidl.plugins.kubeflow.DistributedMPITrainingTask.worker_replicas:type_name -> flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec
	1, // 1: flyteidl.plugins.kubeflow.DistributedMPITrainingTask.launcher_replicas:type_name -> flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec
	2, // 2: flyteidl.plugins.kubeflow.DistributedMPITrainingTask.run_policy:type_name -> flyteidl.plugins.kubeflow.RunPolicy
	3, // 3: flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec.resources:type_name -> flyteidl.core.Resources
	4, // 4: flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec.restart_policy:type_name -> flyteidl.plugins.RestartPolicy
	5, // 5: flyteidl.plugins.kubeflow.DistributedMPITrainingReplicaSpec.common:type_name -> flyteidl.plugins.CommonReplicaSpec
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_flyteidl_plugins_kubeflow_mpi_proto_init() }
func file_flyteidl_plugins_kubeflow_mpi_proto_init() {
	if File_flyteidl_plugins_kubeflow_mpi_proto != nil {
		return
	}
	file_flyteidl_plugins_kubeflow_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DistributedMPITrainingTask); i {
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
		file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DistributedMPITrainingReplicaSpec); i {
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
			RawDescriptor: file_flyteidl_plugins_kubeflow_mpi_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_flyteidl_plugins_kubeflow_mpi_proto_goTypes,
		DependencyIndexes: file_flyteidl_plugins_kubeflow_mpi_proto_depIdxs,
		MessageInfos:      file_flyteidl_plugins_kubeflow_mpi_proto_msgTypes,
	}.Build()
	File_flyteidl_plugins_kubeflow_mpi_proto = out.File
	file_flyteidl_plugins_kubeflow_mpi_proto_rawDesc = nil
	file_flyteidl_plugins_kubeflow_mpi_proto_goTypes = nil
	file_flyteidl_plugins_kubeflow_mpi_proto_depIdxs = nil
}
