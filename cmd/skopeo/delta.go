package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	tardiff "github.com/containers/tar-diff/pkg/tar-diff"
	digest "github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"go.podman.io/image/v5/image"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/pkg/blobinfocache"
	"go.podman.io/image/v5/transports/alltransports"
	"go.podman.io/image/v5/types"
)

const MediaTypeDeltaConfig = "vnd.redhat.delta.config.v1+json"

type deltaOptions struct {
	global                  *globalOptions
	srcImage                *imageOptions
	destImage               *imageOptions
	fallbackConfigMediatype bool
	fallbackLayerMediatype  bool
}

func deltaCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	deprecatedTLSVerifyFlags, deprecatedTLSVerifyOpt := deprecatedTLSVerifyFlags()
	srcImageFlags, srcImageOpts := imageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "src-", "screds")
	destImageFlags, destImageOpts := imageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "dest-", "dcreds")
	opts := deltaOptions{
		global:    global,
		srcImage:  srcImageOpts,
		destImage: destImageOpts,
	}

	cmd := &cobra.Command{
		Use:     "generate-delta [command options] DESTINATION-IMAGE FROM-IMAGE",
		Short:   "Generate deltas for IMAGE-NAME",
		Long:    "Generate delta layers for IMAGE-NAME in a registry. This speeds up downloads of DESTINATION-IMAGE if FROM-IMAGE is locally available at the client.",
		RunE:    commandAction(opts.run),
		Example: "skopeo generate-delta docker://docker.io/fedora docker://docker.io/fedora:previous",
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&deprecatedTLSVerifyFlags)
	flags.AddFlagSet(&srcImageFlags)
	flags.AddFlagSet(&destImageFlags)
	flags.BoolVar(&opts.fallbackConfigMediatype, "fallback-config-type", false, `Use OCI media-type for config instead of delta specific type`)
	flags.BoolVar(&opts.fallbackLayerMediatype, "fallback-layer-type", false, `Use OCI layer media-type for tar-diff blobs instead of tar-diff media-type`)
	return cmd
}

func downloadBlob(ctx context.Context, img types.ImageSource, layer types.BlobInfo, cache types.BlobInfoCache) (*os.File, error) {
	blob, _, err := img.GetBlob(ctx, layer, cache)
	if err != nil {
		return nil, err
	}
	defer blob.Close()

	tmp, err := os.CreateTemp("/var/tmp", "skopeo-blob-")
	if err != nil {
		return nil, err
	}
	// We unlink the tmpfiles, so we're guaranteed cleanup even if we exit early
	os.Remove(tmp.Name())

	_, err = io.Copy(tmp, blob)
	if err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Seek(0, 0) // reset to start
	return tmp, nil
}

func generateDeltaFile(ctx context.Context, toImg types.ImageSource, toLayer types.BlobInfo, fromImg types.ImageSource, fromLayer types.BlobInfo, cache types.BlobInfoCache) (*os.File, error) {
	fmt.Printf("Downloading 'from' blob %v\n", fromLayer.Digest)
	fromTmp, err := downloadBlob(ctx, fromImg, fromLayer, cache)
	if err != nil {
		return nil, err
	}
	defer fromTmp.Close()

	fmt.Printf("Downloading 'to' blob %v\n", toLayer.Digest)
	toTmp, err := downloadBlob(ctx, toImg, toLayer, cache)
	if err != nil {
		return nil, err
	}
	defer toTmp.Close()

	fmt.Printf("Generating delta\n")
	delta, err := os.CreateTemp("/var/tmp", "skopeo-delta-")
	if err != nil {
		return nil, err
	}
	// We unlink the tmpfiles, so we're guaranteed cleanup even if we exit early
	os.Remove(delta.Name())

	err = tardiff.Diff(fromTmp, toTmp, delta, nil)
	if err != nil {
		delta.Close()
		return nil, err
	}
	delta.Seek(0, 0) // reset to start
	return delta, nil
}

func manifestHasDelta(deltaManifest *manifest.OCI1, to digest.Digest, from digest.Digest) bool {
	for i := range deltaManifest.Layers {
		deltaLayer := &deltaManifest.Layers[i]
		existingTo := deltaLayer.Annotations["io.github.containers.delta.to"]
		existingFrom := deltaLayer.Annotations["io.github.containers.delta.from"]

		if existingTo == to.String() && existingFrom == from.String() {
			return true
		}
	}
	return false
}

// This is in its own function mostly so we have a defer context for each generated delta
func generateDeltasForLayer(ctx context.Context, opts *deltaOptions, to *imageVersionInstance, toLayer types.BlobInfo, toDiffID digest.Digest, from *imageVersionInstance, fromLayer types.BlobInfo, fromDiffID digest.Digest, deltaManifest *manifest.OCI1, deltaDestination types.ImageDestination, cache types.BlobInfoCache) (bool, error) {
	fmt.Printf("Generating delta for layer %v from %v\n", toDiffID, fromDiffID)
	delta, err := generateDeltaFile(ctx, to.ImgSrc, toLayer, from.ImgSrc, fromLayer, cache)
	if err != nil {
		return false, err
	}
	defer delta.Close()

	info, err := delta.Stat()
	if err != nil {
		return false, err
	}
	deltaSize := info.Size()
	// Discard deltas that end up being larger or almost as large as the layer
	if deltaSize > toLayer.Size*9/10 {
		fmt.Printf("Generated delta too large, ignoring\n")
		return false, nil
	}

	deltaDigest, err := digest.FromReader(delta)
	if err != nil {
		return false, err
	}
	delta.Seek(0, 0) // reset to start

	fmt.Printf("Generated delta size %.1f MB, original layer %.1f MB\n", float64(deltaSize)/(1024.0*1024), float64(toLayer.Size)/(1024.0*1024.0))

	fmt.Printf("Uploading delta layer %v\n", deltaDigest)
	deltaInfo, err := deltaDestination.PutBlob(ctx, delta, types.BlobInfo{Size: deltaSize, Digest: deltaDigest}, cache, false)
	if err != nil {
		return false, err
	}

	annotations := make(map[string]string)
	annotations["io.github.containers.delta.to"] = toDiffID.String()
	annotations["io.github.containers.delta.from"] = fromDiffID.String()

	mediaType := manifest.MediaTypeTarDiff
	if opts.fallbackLayerMediatype {
		mediaType = v1.MediaTypeImageLayerGzip
	}

	deltaManifest.Layers = append(deltaManifest.Layers, v1.Descriptor{
		MediaType:   mediaType,
		Digest:      deltaInfo.Digest,
		Size:        deltaInfo.Size,
		Annotations: annotations})

	return true, nil
}

func generateDeltasBetween(ctx context.Context, sys *types.SystemContext, opts *deltaOptions, to *imageVersionInstance, from *imageVersionInstance, deltaDestination types.ImageDestination, cache types.BlobInfoCache) (bool, error) {
	deltaManifest, err := ensureDeltaManifest(ctx, sys, opts, to, deltaDestination, cache)
	if err != nil {
		return false, err
	}

	fmt.Printf("Generating deltas for image %v from %v\n", to.Digest, from.Digest)

	updated := false
	for i := range to.Layers {
		toLayer := to.Layers[i]
		toDiffID := to.DiffIDs[i]
		if len(from.Layers) <= i {
			break // from image has less layers than the to, ignore later layers
		}
		fromLayer := from.Layers[i]
		fromDiffID := from.DiffIDs[i]

		if toLayer.Digest == fromLayer.Digest {
			continue // same layer, no need for deltas
		}

		if manifestHasDelta(deltaManifest, toDiffID, fromDiffID) {
			continue // Already in delta manifest
		}

		layerUpdated, err := generateDeltasForLayer(ctx, opts, to, toLayer, toDiffID, from, fromLayer, fromDiffID, deltaManifest, deltaDestination, cache)
		if err != nil {
			return false, err
		}
		if layerUpdated {
			updated = true
		}
	}
	return updated, nil
}

type imageVersionInstance struct {
	ImgSrc       types.ImageSource // Same as the one in the imageVersion, closed there
	Digest       digest.Digest
	Layers       []types.BlobInfo
	Architecture string
	OS           string
	DiffIDs      []digest.Digest
	Platform     *v1.Platform // nil if not index or not set in index

	DeltaManifest *manifest.OCI1 // starts out empty but loaded (and kept around) by ensureDeltaManifest
}

type imageVersion struct {
	ImgSrc           types.ImageSource
	ToplevelUnparsed types.UnparsedImage
	Instances        []imageVersionInstance
}

func (v *imageVersion) Close() error {
	err := v.ImgSrc.Close()
	if err != nil {
		return fmt.Errorf("(could not close image source: %v) ", err)
	}
	return nil
}

func supportedImageType(manifestType string) bool {
	return manifestType == v1.MediaTypeImageManifest || manifestType == manifest.DockerV2Schema2MediaType
}

func doLoadImgVersionInstance(ctx context.Context, toplevelImgSrc types.ImageSource, img types.Image) (*imageVersionInstance, error) {
	manifestBytes, manifestType, err := img.Manifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest for image: %w", err)
	}

	if !supportedImageType(manifestType) {
		return nil, nil // Not error, but also no supported instance
	}

	manifestDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest for image: %w", err)
	}

	layers := img.LayerInfos()

	config, err := img.OCIConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("parsing config for image: %w", err)
	}
	diffIDs := config.RootFS.DiffIDs

	if len(layers) != len(diffIDs) {
		return nil, fmt.Errorf("number of layers in image doesn't match number of DiffIDs")
	}

	return &imageVersionInstance{
		ImgSrc:       toplevelImgSrc,
		Digest:       manifestDigest,
		Layers:       layers,
		Architecture: config.Architecture,
		OS:           config.OS,
		DiffIDs:      diffIDs,
		Platform:     nil,
	}, nil
}

func loadImgVersionInstancesForIndex(ctx context.Context, sys *types.SystemContext, toplevelImgSrc types.ImageSource, index *manifest.OCI1Index) ([]imageVersionInstance, error) {
	instances := make([]imageVersionInstance, 0)
	for _, indexManifest := range index.Manifests {
		unparsed := image.UnparsedInstance(toplevelImgSrc, &indexManifest.Digest)
		img, err := image.FromUnparsedImage(ctx, sys, unparsed)
		if err != nil {
			return nil, fmt.Errorf("parsing manifest for image: %w", err)
		}

		instance, err := doLoadImgVersionInstance(ctx, toplevelImgSrc, img)
		if err != nil {
			return nil, err
		}
		if instance != nil {
			instance.Platform = indexManifest.Platform
			instances = append(instances, *instance)
		}
	}

	return instances, nil
}

func loadImgVersion(ctx context.Context, sys *types.SystemContext, name string) (retVal *imageVersion, retErr error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		return nil, fmt.Errorf("parsing image name %q: %w", name, err)
	}

	toplevelImgSrc, err := ref.NewImageSource(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("creating image: %w", err)
	}
	defer func() {
		if retVal == nil {
			toplevelImgSrc.Close()
		}
	}()

	toplevelUnparsed := image.UnparsedInstance(toplevelImgSrc, nil)
	toplevelImg, err := image.FromUnparsedImage(ctx, sys, toplevelUnparsed)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest for image %v: %w", name, err)
	}

	manifestBytes, manifestType, err := toplevelImg.Manifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest for image %v: %w", name, err)
	}

	var instances []imageVersionInstance

	if manifestType == v1.MediaTypeImageIndex {
		index, err := manifest.OCI1IndexFromManifest(manifestBytes)
		if err != nil {
			return nil, err
		}

		instances, err = loadImgVersionInstancesForIndex(ctx, sys, toplevelImgSrc, index)
		if err != nil {
			return nil, err
		}

	} else if manifestType == manifest.DockerV2ListMediaType {
		list, err := manifest.Schema2ListFromManifest(manifestBytes)
		if err != nil {
			return nil, err
		}
		index, err := list.ToOCI1Index()
		if err != nil {
			return nil, err
		}

		instances, err = loadImgVersionInstancesForIndex(ctx, sys, toplevelImgSrc, index)
		if err != nil {
			return nil, err
		}
	} else if supportedImageType(manifestType) {
		// Single image

		instance, err := doLoadImgVersionInstance(ctx, toplevelImgSrc, toplevelImg)
		if err != nil {
			return nil, err
		}
		instances = make([]imageVersionInstance, 1)
		instances[0] = *instance
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no supported image manifests in %v", name)
	}

	return &imageVersion{
		ImgSrc:           toplevelImgSrc,
		ToplevelUnparsed: toplevelUnparsed,
		Instances:        instances,
	}, nil
}

func ensureDeltaIndex(ctx context.Context, sys *types.SystemContext, indexRef types.ImageReference) (*manifest.OCI1Index, error) {
	// We assume any error here means "no such manifest"
	// Maybe we could detect the exact error (vs temporary network errors) somehow?
	indexSrc, err := indexRef.NewImageSource(ctx, sys)
	if err != nil {
		// Create a new index
		return manifest.OCI1IndexFromComponents(nil, nil), nil
	}
	defer indexSrc.Close()

	index, indexType, err := indexSrc.GetManifest(ctx, nil)
	if err != nil {
		return nil, err
	}

	if indexType != v1.MediaTypeImageIndex {
		return nil, fmt.Errorf("unexpected media type %v for existing delta manifest", indexType)
	}

	return manifest.OCI1IndexFromManifest(index)
}

func ensureIndexDeltaDescriptorForTarget(index *manifest.OCI1Index, to *imageVersionInstance) *v1.Descriptor {
	deltaTarget := to.Digest.String()
	// Find existing descriptor for the target, if it exists
	for _, manifest := range index.Manifests {
		if manifest.Annotations["io.github.containers.delta.target"] == deltaTarget {
			return &manifest
		}
	}

	// Otherwise create new descriptor
	index.Manifests = append(index.Manifests, v1.Descriptor{
		Platform: &v1.Platform{
			Architecture: to.Architecture,
			OS:           to.OS,
		},
	})
	return &index.Manifests[len(index.Manifests)-1]
}

func addToDeltaIndex(ctx context.Context, sys *types.SystemContext, index *manifest.OCI1Index, to *imageVersionInstance, deltaDestination types.ImageDestination) error {
	deltaManifestBytes, err := to.DeltaManifest.Serialize()
	if err != nil {
		return err
	}
	deltaManifestDigest, err := manifest.Digest(deltaManifestBytes)
	if err != nil {
		return err
	}

	err = deltaDestination.PutManifest(ctx, deltaManifestBytes, &deltaManifestDigest)
	if err != nil {
		return err
	}

	indexDescriptor := ensureIndexDeltaDescriptorForTarget(index, to)

	indexDescriptor.MediaType = v1.MediaTypeImageManifest
	indexDescriptor.Digest = deltaManifestDigest
	indexDescriptor.Size = int64(len(deltaManifestBytes))
	if indexDescriptor.Annotations == nil {
		indexDescriptor.Annotations = make(map[string]string)
	}
	indexDescriptor.Annotations["io.github.containers.delta.target"] = to.Digest.String()

	return nil
}

func ensureDeltaManifest(ctx context.Context, sys *types.SystemContext, opts *deltaOptions, to *imageVersionInstance, deltaDestination types.ImageDestination, cache types.BlobInfoCache) (*manifest.OCI1, error) {
	if to.DeltaManifest != nil {
		return to.DeltaManifest, nil
	}

	// Maybe there is already some deltas for this image, if so we want to append to them
	deltaManifestBytes, manifestType, err := types.ImageSourceGetDeltaManifest(to.ImgSrc, ctx, &to.Digest)
	if err != nil {
		return nil, err
	}

	if deltaManifestBytes != nil {
		if manifestType != v1.MediaTypeImageManifest {
			return nil, fmt.Errorf("unsupported type of existing delta manifest")
		}
		deltaManifest, err := manifest.OCI1FromManifest(deltaManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing delta manifest: %w", err)
		}
		return deltaManifest, nil
	}

	mediaType := MediaTypeDeltaConfig
	configBytes := []byte("{}")
	if opts.fallbackConfigMediatype {
		// Used when e.g. target doesn't support OCI artifacts
		mediaType = v1.MediaTypeImageConfig
		config := v1.Image{
			Platform: v1.Platform{
				Architecture: to.Architecture,
				OS:           to.OS,
			},
			RootFS: v1.RootFS{
				Type:    "layers",
				DiffIDs: make([]digest.Digest, 0),
			},
		}
		configBytes, err = json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("marshaling config %#v: %w", config, err)
		}
	}
	configDigest, err := manifest.Digest(configBytes)
	if err != nil {
		return nil, err
	}

	configInfo, err := deltaDestination.PutBlob(ctx, bytes.NewReader(configBytes), types.BlobInfo{Digest: configDigest, Size: int64(len(configBytes))}, cache, true)

	m := manifest.OCI1FromComponents(
		v1.Descriptor{
			MediaType: mediaType,
			Digest:    configInfo.Digest,
			Size:      configInfo.Size,
			Platform: &v1.Platform{
				Architecture: to.Architecture,
				OS:           to.OS,
			},
		}, make([]v1.Descriptor, 0))
	m.Annotations = map[string]string{
		"io.github.containers.delta.target": to.Digest.String(),
	}

	to.DeltaManifest = m
	return m, nil
}

func featuresEqual(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func matchingInstance(a *imageVersionInstance, b *imageVersionInstance, fuzzyLevel int) bool {
	aP := a.Platform
	bP := b.Platform

	// Never match unspecified platforms (uncommon for indexes, but always for non-indexed images)
	if a.Platform == nil || b.Platform == nil {
		return false
	}

	if fuzzyLevel == 0 {
		// Exact match
		return aP.Architecture == bP.Architecture &&
			aP.OS == bP.OS &&
			aP.OSVersion == bP.OSVersion &&
			featuresEqual(aP.OSFeatures, bP.OSFeatures) &&
			aP.Variant == bP.Variant
	} else if fuzzyLevel == 1 {
		// os/platform and variant match
		return aP.Architecture == bP.Architecture &&
			aP.OS == bP.OS &&
			aP.Variant == bP.Variant
	} else {
		// os/platform match
		return aP.Architecture == bP.Architecture &&
			aP.OS == bP.OS
	}
}

func pickInstanceFor(instance *imageVersionInstance, available []imageVersionInstance, matchSingle bool) *imageVersionInstance {
	// 1-to-1, always matching if matchSingle
	if matchSingle && len(available) == 1 {
		return &available[0]
	}

	// In decreasing order of fuzziness, match on platform
	for fuzzyLevel := 0; fuzzyLevel < 3; fuzzyLevel++ {
		for i := range available {
			if matchingInstance(instance, &available[i], fuzzyLevel) {
				return &available[i]
			}
		}
	}

	// No good enough matching
	return nil
}

func generateDeltas(ctx context.Context, sys *types.SystemContext, opts *deltaOptions, to *imageVersion, from *imageVersion, deltaDestination types.ImageDestination, cache types.BlobInfoCache) (bool, error) {
	if len(to.Instances) == 0 || len(from.Instances) == 0 {
		return false, nil // Nothing to do
	}

	anyUpdated := false

	for i := range to.Instances {
		toInstance := &to.Instances[i]
		// Only allow single-from-instance match (that don't match platform) if to is single-image
		fromInstance := pickInstanceFor(toInstance, from.Instances, len(to.Instances) == 1)
		if fromInstance == nil {
			fmt.Printf("No delta source for image %v\n", toInstance.Digest)
			continue
		}
		instanceUpdated, err := generateDeltasBetween(ctx, sys, opts, toInstance, fromInstance, deltaDestination, cache)
		if err != nil {
			return false, err
		}
		if instanceUpdated {
			anyUpdated = true
		}
	}

	return anyUpdated, nil
}

func (opts *deltaOptions) run(args []string, stdout io.Writer) (retErr error) {
	if len(args) != 2 {
		return errorShouldDisplayUsage{errors.New("exactly two arguments expected")}
	}
	imageNames := args

	policyContext, err := opts.global.getPolicyContext()
	if err != nil {
		return fmt.Errorf("loading trust policy: %w", err)
	}
	defer policyContext.Destroy()

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	srcSys, err := opts.srcImage.newSystemContext()
	if err != nil {
		return err
	}

	destSys, err := opts.destImage.newSystemContext()
	if err != nil {
		return err
	}

	cache := blobinfocache.DefaultCache(destSys)

	to, err := loadImgVersion(ctx, destSys, imageNames[0])
	if err != nil {
		return err
	}
	defer func() {
		if err := to.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	deltaIndexRef, err := types.ImageSourceGetDeltaIndex(to.ImgSrc, ctx)
	if err != nil {
		return err
	}
	if deltaIndexRef == nil {
		return fmt.Errorf("destination does not support deltas")
	}

	deltaDestination, err := deltaIndexRef.NewImageDestination(ctx, destSys)
	if err != nil {
		return err
	}
	defer deltaDestination.Close()

	from, err := loadImgVersion(ctx, srcSys, imageNames[1])
	if err != nil {
		return err
	}
	defer func() {
		if err := from.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	updated, err := generateDeltas(ctx, destSys, opts, to, from, deltaDestination, cache)
	if err != nil {
		return err
	}

	if updated {
		fmt.Printf("Updating delta manifest\n")

		index, err := ensureDeltaIndex(ctx, destSys, deltaIndexRef)
		if err != nil {
			return err
		}

		for i := range to.Instances {
			if to.Instances[i].DeltaManifest != nil {
				err = addToDeltaIndex(ctx, destSys, index, &to.Instances[i], deltaDestination)
				if err != nil {
					return err
				}
			}
		}

		indexBytes, err := index.Serialize()
		if err != nil {
			return err
		}

		err = deltaDestination.PutManifest(ctx, indexBytes, nil)
		if err != nil {
			return err
		}

		err = deltaDestination.Commit(ctx, to.ToplevelUnparsed)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("No new deltas, not uploading manifest\n")
	}

	return nil
}
