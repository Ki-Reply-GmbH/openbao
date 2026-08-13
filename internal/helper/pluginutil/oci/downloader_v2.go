// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/klauspost/compress/zstd"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/osutil"
)

const (
	PluginCacheDirV1 = ".oci-cache"
	PluginCacheDirV2 = ".oci-cache-v2"

	PluginMaxSizeBytes = 512 * 1024 * 1024 // 512 MB

	indexSentinel = "index"
	imageSentinel = "image"
)

// PluginDownloader handles downloading and managing OCI-based plugins
type PluginDownloader struct {
	pluginDirectory string
	config          *server.Config
	logger          hclog.Logger
}

// NewPluginDownloader creates a new OCI plugin downloader
func NewPluginDownloader(pluginDirectory string, config *server.Config, logger hclog.Logger) *PluginDownloader {
	return &PluginDownloader{
		pluginDirectory: pluginDirectory,
		config:          config,
		logger:          logger,
	}
}

// ReconcilePlugins downloads and validates all configured OCI plugins.
func (d *PluginDownloader) ReconcilePlugins(ctx context.Context) error {
	plugins := d.config.Plugins
	if len(plugins) == 0 {
		d.logger.Debug("no plugin configuration found")
		return nil
	}

	if d.pluginDirectory == "" {
		return errors.New("plugin directory is not configured")
	}

	platform, err := v1.ParsePlatform(platforms.DefaultString())
	if err != nil {
		return fmt.Errorf("failed to detect local platform: %w", err)
	}

	for _, pluginConfig := range plugins {
		// Skip plugins which are manually downloaded but defined declaratively.
		if pluginConfig.Image == "" {
			continue
		}

		pluginLogger := d.logger.With("plugin", pluginConfig.Slug())
		configErr := pluginConfig.Validate("")

		// Display configuration errors if any.
		for _, configError := range configErr {
			d.logger.Error(configError.String())
		}

		if len(configErr) > 0 {
			if d.shouldFailOnPluginError() {
				return fmt.Errorf("plugin %s %s: config not valid", pluginConfig.Type, pluginConfig.Name)
			} else {
				pluginLogger.Warn("plugin config not valid")
				continue
			}
		}

		pluginLogger.Debug("processing plugin", "image", pluginConfig.Image, "version", pluginConfig.Version)

		// Fast path: check if plugin already exists.
		if d.IsPluginCacheValid(pluginConfig, platform) {
			pluginLogger.Info("plugin is cached on disk, skipping download")
			continue
		}

		// Slow path: download from OCI registry.
		if err := d.DownloadPlugin(ctx, pluginConfig, pluginLogger, platform); err != nil {
			if d.shouldFailOnPluginError() {
				return fmt.Errorf("failed to download plugin %q: %w", pluginConfig.Slug(), err)
			} else {
				pluginLogger.Warn("failed to download plugin", "error", err)
				continue
			}
		}
	}

	return nil
}

// shouldFailOnPluginError determines whether plugin download errors should fail startup
func (d *PluginDownloader) shouldFailOnPluginError() bool {
	behavior := d.config.PluginDownloadBehavior
	if behavior == "" {
		behavior = server.PluginDownloadFail
	}

	return behavior == server.PluginDownloadFail
}

// maxPluginSize returns the maximum allowed plugin binary size
func (d *PluginDownloader) maxPluginSize() int64 {
	if d.config.PluginDownloadMaxSize > 0 {
		return d.config.PluginDownloadMaxSize
	}

	return PluginMaxSizeBytes
}

func (d *PluginDownloader) binaryNameFallback(c *v1.ConfigFile) (string, error) {
	switch {
	case len(c.Config.Entrypoint) > 0:
		return strings.TrimPrefix(c.Config.Entrypoint[0], "/"), nil
	case len(c.Config.Cmd) > 0:
		return strings.TrimPrefix(c.Config.Cmd[0], "/"), nil
	}
	return "", errors.New("failed to determine binary name within OCI image, either add entrypoint to image or explicitly set binary name")
}

// IsPluginCacheValid checks if the plugin already exists in the plugin
// directory and matches a binary SHA256 in the legacy cache or is present in
// the OCI layout dir and was extracted into the plugin directory.
func (d *PluginDownloader) IsPluginCacheValid(config *server.PluginConfig, platform *v1.Platform) bool {
	if d.pluginDirectory == "" {
		return false
	}

	// Check if a file (symlink from PluginLegacyCacheDir or hard copy from
	// PluginOCILayoutDir) exists at the top-level of the plugin directory.
	pluginPath := filepath.Join(d.pluginDirectory, config.FullName())

	// Check if symlink or not.
	linkInfo, err := os.Lstat(pluginPath)
	if err != nil {
		return false
	}

	symlink := linkInfo.Mode()&os.ModeSymlink != 0

	if symlink {
		// Follow the symlink to get the actual cached file.
		cachedFilePath, err := os.Readlink(pluginPath)
		if err != nil {
			return false
		}

		// Make sure it's an absolute path.
		if !filepath.IsAbs(cachedFilePath) {
			cachedFilePath = filepath.Join(d.pluginDirectory, cachedFilePath)
		}

		// Check if the cached file exists
		if _, err := os.Stat(cachedFilePath); os.IsNotExist(err) {
			return false
		}

		pluginPath = cachedFilePath
	}

	// Keep this digest around to later check against the hash of the binary
	// that would extract from the OCI layout dir if the image is present there.
	binaryDigest, err := osutil.FileSha256Sum(pluginPath)
	if err != nil {
		d.logger.Debug("failed to calculate plugin hash", "plugin", config.Slug(), "error", err)
		return false
	}

	// Validate SHA256 of the plugin binary if manually set in config.
	if len(config.SHA256Sum) > 0 {
		// We're done at this point, for simplicity's sake. Note that if we've
		// found a matching *binary* SHA256 here, we have not validated whether
		// the *image* SHA256 matches, if it is pinned. Lack of revalidation
		// here should be acceptable given the user explicitly pinned the binary
		// itself, which we'll prioritize.
		return strings.EqualFold(binaryDigest, config.SHA256Sum)
	}

	if symlink {
		// Symlinks created to point into PluginLegacyCacheDir must always come
		// with a SHA256Sum to be considered valid.
		return false
	}

	digest, err := name.NewDigest(config.Image)
	if err != nil {
		return false
	}
	hash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return false
	}

	ociCachePath := filepath.Join(d.pluginDirectory, PluginCacheDirV2, digest.Identifier())
	ociCacheFile, err := os.Open(ociCachePath)
	if err != nil {
		return false
	}

	tarReader := tar.NewReader(ociCacheFile)

	// Read the initial header, which is the index sentinel.
	header, err := tarReader.Next()
	if err != nil {
		return false
	}
	// It should be zero-sized.
	if header.Size != 0 {
		return false
	}

	var imageManifest *v1.Manifest

	switch header.Name {
	case imageSentinel:
		imageManifest, err = readImageManifest(tarReader, hash)
		if err != nil {
			return false
		}
	case indexSentinel:
		for {
			indexManifest, err := readIndexManifest(tarReader, hash)
			if err != nil {
				return false
			}

			var next *v1.Descriptor
			for _, m := range indexManifest.Manifests {
				if !m.Platform.Equals(*platform) {
					continue
				}
				if m.MediaType.IsImage() || m.MediaType.IsIndex() {
					next = &m
					break
				}
			}

			if next == nil {
				return false
			}

			if next.MediaType.IsImage() {
				imageManifest, err = readImageManifest(tarReader, next.Digest)
				if err != nil {
					return false
				}
				break
			}

			if next.MediaType.IsIndex() {
				hash = next.Digest
				continue
			}
		}
	default:
		return false
	}

	configFile, err := readImageConfig(tarReader, imageManifest.Config.Digest)
	if err != nil {
		return false
	}

	header, err = tarReader.Next()
	if err != nil {
		return false
	}

	layerDigest, err := v1.NewHash(header.Name)
	if err != nil {
		return false
	}

	layerIndex := slices.IndexFunc(imageManifest.Layers, func(layer v1.Descriptor) bool {
		return layer.Digest == layerDigest
	})

	if layerIndex == -1 {
		return false
	}

	layer := imageManifest.Layers[layerIndex]

	binaryName := config.BinaryName
	if binaryName == "" {
		if binaryName, err = d.binaryNameFallback(configFile); err != nil {
			return false
		}
	}

	layerHasher := sha256.New()
	compressedReader := io.TeeReader(tarReader, layerHasher)

	var uncompressedReader io.Reader
	switch layer.MediaType {
	case types.OCILayerZStd:
		uncompressedReader, err = zstd.NewReader(compressedReader)
	case types.OCILayer, types.DockerLayer:
		uncompressedReader, err = gzip.NewReader(compressedReader)
	case types.OCIUncompressedLayer, types.DockerUncompressedLayer:
		uncompressedReader = compressedReader
	default:
		return false
	}

	innerTarReader := tar.NewReader(uncompressedReader)
	for {
		header, err := innerTarReader.Next()
		if err != nil {
			return false
		}

		// Normalize the path by removing leading slashes.
		normalizedPath := strings.TrimPrefix(header.Name, "/")
		// Check if this is our target binary.
		if normalizedPath != binaryName && header.Name != binaryName {
			continue
		}
		// Check if it's a regular file.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		binaryHasher := sha256.New()
		if _, err := io.Copy(binaryHasher, innerTarReader); err != nil {
			return false
		}

		if !strings.EqualFold(binaryDigest, hex.EncodeToString(binaryHasher.Sum(nil))) {
			return false
		}

		break
	}

	if _, err := io.Copy(io.Discard, compressedReader); err != nil {
		return false
	}

	sha, err := hex.DecodeString(layer.Digest.Hex)
	if err != nil {
		return false
	}

	return bytes.Equal(layerHasher.Sum(nil), sha)
}

func readWithDigest(tr *tar.Reader, digest v1.Hash, f func(r io.Reader) error) error {
	if digest.Algorithm != "sha256" {
		return errors.New("only sha256 digests are supported")
	}

	sha, err := hex.DecodeString(digest.Hex)
	if err != nil {
		return err
	}

	header, err := tr.Next()
	if err != nil {
		return err
	}

	if !strings.EqualFold(header.Name, digest.String()) {
		return errors.New("invalid sha256")
	}

	h := sha256.New()
	err = f(io.TeeReader(tr, h))

	switch {
	case err != nil:
		return err
	case !bytes.Equal(h.Sum(nil), sha):
		return errors.New("invalid sha256")
	}

	return nil
}

func readIndexManifest(tr *tar.Reader, digest v1.Hash) (m *v1.IndexManifest, err error) {
	err = readWithDigest(tr, digest, func(r io.Reader) error {
		m, err = v1.ParseIndexManifest(r)
		return err
	})
	return m, err
}

func readImageManifest(tr *tar.Reader, digest v1.Hash) (m *v1.Manifest, err error) {
	err = readWithDigest(tr, digest, func(r io.Reader) error {
		m, err = v1.ParseManifest(r)
		return err
	})
	return m, err
}

func readImageConfig(tr *tar.Reader, digest v1.Hash) (c *v1.ConfigFile, err error) {
	err = readWithDigest(tr, digest, func(r io.Reader) error {
		c, err = v1.ParseConfigFile(r)
		return err
	})
	return c, err
}

// DownloadPlugin downloads a plugin from an OCI registry, storing its image
// in PluginOCILayoutDir and extracting its binary into the plugin directory's
// toplevel.
func (d *PluginDownloader) DownloadPlugin(ctx context.Context, config *server.PluginConfig, logger hclog.Logger, platform *v1.Platform) error {
	// Start by resolving the image reference.
	var ref name.Reference
	// Prioritize digest references.
	ref, err := name.NewDigest(config.Image)
	if err != nil {
		// If not a digest reference, retry as a tag reference and fall back to
		// the version field if none was set as part of the image field.
		ref, err = name.NewTag(config.Image, name.WithDefaultTag(config.Version))
		if err != nil {
			return fmt.Errorf("invalid OCI reference %q: %w", config.Image, err)
		}
	}

	var img v1.Image

	// Record a list of manifests that are traversed to cache them later.
	type manifest struct {
		digest  string
		content []byte
		isIndex bool
	}
	var manifests []manifest

	for {
		// Fetch the opaque descriptor.
		desc, err := remote.Get(
			ref,
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		)
		if err != nil {
			return fmt.Errorf("failed to fetch OCI descriptor: %w", err)
		}

		switch {
		case desc.MediaType.IsIndex():
		case desc.MediaType.IsImage():
			img, err = desc.Image()
		default:
			err = fmt.Errorf("bad media type")
		}

		if img != nil {
			manifests = append(manifests, manifest{
				digest:  desc.Digest.String(),
				content: desc.Manifest,
			})
			break
		}
		if err != nil {
			return err
		}

		manifests = append(manifests, manifest{
			digest:  desc.Digest.String(),
			content: desc.Manifest,
			isIndex: true,
		})

		index, err := desc.ImageIndex()
		if err != nil {
			return err
		}
		indexManifest, err := index.IndexManifest()
		if err != nil {
			return err
		}

		// Find the next descriptor, either a nested index manifest or an image
		// manifest.
		var next *v1.Descriptor
		for _, m := range indexManifest.Manifests {
			if m.Platform.Equals(*platform) && m.MediaType.IsImage() || m.MediaType.IsIndex() {
				next = &m
				break
			}
		}

		if next == nil {
			return errors.New("no matching thing found")
		}

		ref = ref.Context().Digest(next.Digest.String())
	}

	if err := os.MkdirAll(filepath.Join(d.pluginDirectory, PluginCacheDirV2), 0755); err != nil {
		return err
	}

	pluginPath := filepath.Join(d.pluginDirectory, config.FullName())
	pluginFile, err := os.OpenFile(pluginPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}

	ociCachePath := filepath.Join(d.pluginDirectory, PluginCacheDirV2, manifests[0].digest)
	ociCacheFile, err := os.OpenFile(ociCachePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	configDigest, err := img.ConfigName()
	if err != nil {
		return err
	}
	configFile, err := img.ConfigFile()
	if err != nil {
		return err
	}
	rawConfigFile, err := img.RawConfigFile()
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return err
	}

	binaryName := config.BinaryName
	if binaryName == "" {
		if binaryName, err = d.binaryNameFallback(configFile); err != nil {
			return err
		}
	}

	// Traverse layers, looking for the one containing our plugin binary. Move
	// in reverse order since later layers are more likely to contain the plugin
	// binary, e.g., if this is image is not based on scratch for some reason.
	for _, layer := range slices.Backward(layers) {
		var compressedReader io.Reader

		compressedReader, err := layer.Compressed()
		if err != nil {
			return err
		}

		sz, err := layer.Size()
		if err != nil {
			return err
		}

		mt, err := layer.MediaType()
		if err != nil {
			return err
		}

		digest, err := layer.Digest()
		if err != nil {
			return err
		}

		tarWriter := tar.NewWriter(ociCacheFile)
		gatedWriter := gatedwriter.NewWriter(tarWriter)

		compressedReader = io.TeeReader(compressedReader, gatedWriter)

		var uncompressedReader io.Reader
		switch mt {
		case types.OCILayerZStd:
			uncompressedReader, err = zstd.NewReader(compressedReader)
		case types.OCILayer, types.DockerLayer:
			uncompressedReader, err = gzip.NewReader(compressedReader)
		case types.OCIUncompressedLayer, types.DockerUncompressedLayer:
			uncompressedReader = compressedReader
		default:
			continue
		}

		if err != nil {
			return err
		}

		tarReader := tar.NewReader(uncompressedReader)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading tar entry: %w", err)
			}

			// Normalize the path by removing leading slashes.
			normalizedPath := strings.TrimPrefix(header.Name, "/")
			// Check if this is our target binary.
			if normalizedPath != binaryName && header.Name != binaryName {
				continue
			}
			// Check if it's a regular file.
			if header.Typeflag != tar.TypeReg {
				continue
			}

			if header.Size > d.maxPluginSize() {
				return fmt.Errorf("plugin binary size of %d MiB exceeds allowed size of %d MiB", header.Size/1024/1024, d.maxPluginSize()/1024/1024)
			}

			sentinel := imageSentinel
			if manifests[0].isIndex {
				sentinel = indexSentinel
			}

			if err := tarWriter.WriteHeader(&tar.Header{
				Name: sentinel,
				Mode: 0o644,
			}); err != nil {
				return err
			}

			// Write the chain of manifests out to cache.
			for _, m := range manifests {
				if err := tarWriter.WriteHeader(&tar.Header{
					Name: m.digest,
					Size: int64(len(m.content)),
					Mode: 0o644,
				}); err != nil {
					return err
				}
				if _, err := tarWriter.Write(m.content); err != nil {
					return err
				}
			}

			// Next, write the image's config right behind the manifests.
			if err := tarWriter.WriteHeader(&tar.Header{
				Name: configDigest.String(),
				Size: int64(len(rawConfigFile)),
				Mode: 0o644,
			}); err != nil {
				return err
			}
			if _, err := tarWriter.Write(rawConfigFile); err != nil {
				return err
			}

			if err := tarWriter.WriteHeader(&tar.Header{
				Name: digest.String(),
				Size: sz,
				Mode: 0o644,
			}); err != nil {
				return err
			}

			if err := gatedWriter.Flush(); err != nil {
				return err
			}

			n, err := io.Copy(pluginFile, io.LimitReader(tarReader, header.Size+1))
			if err != nil {
				return err
			}
			if n != header.Size {
				return fmt.Errorf("file size was different than reported in tar header")
			}

			if _, err := io.Copy(io.Discard, compressedReader); err != nil {
				return err
			}

			if err := tarWriter.Flush(); err != nil {
				return err
			}

			return nil
		}
	}

	// If a plugin binary SHA256 is configured, validate that.
	if len(config.SHA256Sum) > 0 {
		actualHash, err := osutil.FileSha256Sum(pluginPath)
		if err != nil {
			// Clean up the cached file if hash creation fails.
			removeErr := os.Remove(pluginPath)
			if removeErr != nil {
				return errors.Join(fmt.Errorf("failed to calculate plugin hash: %w", err),
					fmt.Errorf("failed to remove plugin binary: %w", removeErr))
			}
			return fmt.Errorf("failed to calculate plugin hash: %w", err)
		}

		if !strings.EqualFold(actualHash, config.SHA256Sum) {
			// Clean up the cached file if hash doesn't match.
			removeErr := os.Remove(pluginPath)
			if removeErr != nil {
				return errors.Join(fmt.Errorf("plugin hash mismatch: expected %s, got %s", config.SHA256Sum, actualHash),
					fmt.Errorf("failed to remove plugin binary: %w", removeErr))
			}
			return fmt.Errorf("plugin hash mismatch: expected %s, got %s", config.SHA256Sum, actualHash)
		}
	}

	logger.Info("successfully downloaded and validated plugin", "path", pluginPath)

	return nil
}
