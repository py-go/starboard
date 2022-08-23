package kube

import (
	"fmt"
	"hash"
	"hash/fnv"
	"k8s.io/utils/pointer"
	"time"

	"github.com/danielpacak/kube-security-manager/pkg/starboard"
	"github.com/davecgh/go-spew/spew"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/rand"
)

// GetContainerImagesFromPodSpec returns a map of container names
// to container images from the specified v1.PodSpec.
func GetContainerImagesFromPodSpec(spec corev1.PodSpec) ContainerImages {
	images := ContainerImages{}
	for _, container := range spec.Containers {
		images[container.Name] = container.Image
	}
	return images
}

// GetContainerImagesFromJob returns a map of container names
// to container images from the specified v1.Job.
// The mapping is encoded as JSON value of the AnnotationContainerImages
// annotation.
func GetContainerImagesFromJob(job *batchv1.Job) (ContainerImages, error) {
	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[starboard.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("required annotation not set: %s", starboard.AnnotationContainerImages)
	}
	containerImages := ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing annotation: %s: %w", starboard.AnnotationContainerImages, err)
	}
	return containerImages, nil
}

// ComputeHash returns a hash value calculated from a given object.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(obj interface{}) string {
	podSpecHasher := fnv.New32a()
	DeepHashObject(podSpecHasher, obj)
	return rand.SafeEncodeString(fmt.Sprint(podSpecHasher.Sum32()))
}

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

func GetActiveDeadlineSeconds(d time.Duration) *int64 {
	if d > 0 {
		return pointer.Int64Ptr(int64(d.Seconds()))
	}
	return nil
}
