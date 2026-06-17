package data

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/flyteorg/flyte/flytestdlib/logger"
	"github.com/flyteorg/flyte/flytestdlib/storage"
)

// Checks if the given filepath is a valid and existing file path. If ignoreExtension is true, then the dir + basepath is checked for existence
// ignoring the extension.
// In the return the first return value is the actual path that exists (with the extension), second argument is the file info and finally the error
func IsFileReadable(fpath string, ignoreExtension bool) (string, os.FileInfo, error) {
	info, err := os.Stat(fpath)
	if err != nil {
		if os.IsNotExist(err) {
			if ignoreExtension {
				logger.Infof(context.TODO(), "looking for any extensions")
				matches, err := filepath.Glob(fpath + ".*")
				if err == nil && len(matches) == 1 {
					logger.Infof(context.TODO(), "Extension match found [%s]", matches[0])
					info, err = os.Stat(matches[0])
					if err == nil {
						return matches[0], info, nil
					}
				} else {
					logger.Errorf(context.TODO(), "Extension match not found [%v,%v]", err, matches)
				}
			}
			return "", nil, errors.Wrapf(err, "file not found at path [%s]", fpath)
		}
		if os.IsPermission(err) {
			return "", nil, errors.Wrapf(err, "unable to read file [%s], Flyte does not have permissions", fpath)
		}
		return "", nil, errors.Wrapf(err, "failed to read file")
	}
	return fpath, info, nil
}

func allowedDirectoriesForFilePaths(allowedDirectories []string, filePaths ...string) []string {
	roots := append([]string(nil), allowedDirectories...)
	for _, filePath := range filePaths {
		if filePath == "" {
			continue
		}
		if _, _, err := resolvePathInAllowedRoots(filePath, roots); err == nil {
			continue
		}
		dir := filepath.Clean(filePath)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			roots = append(roots, dir)
			continue
		}
		roots = append(roots, filepath.Clean(filepath.Dir(filePath)))
	}
	return roots
}

func resolvePathInAllowedRoots(filePath string, allowedDirectories []string) (root string, rel string, err error) {
	cleanPath := filepath.Clean(filePath)
	for _, dir := range allowedDirectories {
		cleanDir := filepath.Clean(dir)
		relativePath, relErr := filepath.Rel(cleanDir, cleanPath)
		if relErr != nil || strings.HasPrefix(relativePath, "..") {
			continue
		}
		if len(cleanDir) > len(root) {
			root = cleanDir
			rel = relativePath
		}
	}
	if root == "" {
		return "", "", errors.Errorf("path does not start with an allowed prefix, path: %s", cleanPath)
	}
	return root, rel, nil
}

func openFileInAllowedRoot(filePath string, allowedDirectories []string) (*os.File, error) {
	root, rel, err := resolvePathInAllowedRoots(filePath, allowedDirectories)
	if err != nil {
		return nil, err
	}
	return os.OpenInRoot(root, rel)
}

func createFileInAllowedRoot(filePath string, allowedDirectories []string) (*os.File, error) {
	root, rel, err := resolvePathInAllowedRoots(filePath, allowedDirectories)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, os.ModePerm); err != nil {
		return nil, errors.Wrapf(err, "failed to make dir at path %s", root)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	dir := filepath.Dir(rel)
	if dir != "." {
		if err := r.MkdirAll(dir, os.ModePerm); err != nil {
			return nil, errors.Wrapf(err, "failed to make dir at path %s", dir)
		}
		if err := r.Chmod(dir, os.ModePerm); err != nil {
			return nil, errors.Wrapf(err, "failed to chmod directory at path %s", dir)
		}
	}
	writer, err := r.Create(rel)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create file at path %s", filePath)
	}
	return writer, nil
}

// Uploads a file to the data store.
func UploadFileToStorage(ctx context.Context, filePath string, toPath storage.DataReference, size int64, store *storage.DataStore) error {
	f, err := openFileInAllowedRoot(filePath, allowedDirectoriesForFilePaths(AllowedDirectories, filePath))
	if err != nil {
		return err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			logger.Errorf(ctx, "failed to close blob file at path [%s]", filePath)
		}
	}()
	return store.WriteRaw(ctx, toPath, size, storage.Options{}, f)
}

func DownloadFileFromStorage(ctx context.Context, ref storage.DataReference, localPath string, store *storage.DataStore) error {
	m, err := store.Head(ctx, ref)
	if err != nil {
		return errors.Wrapf(err, "failed when looking up Blob")
	}
	if !m.Exists() {
		return fmt.Errorf("incorrect blob reference, does not exist")
	}
	reader, err := store.ReadRaw(ctx, ref)
	if err != nil {
		return errors.Wrapf(err, "failed to read Blob from storage")
	}
	defer func() {
		if err := reader.Close(); err != nil {
			logger.Errorf(ctx, "failed to close Blob read stream @ref [%s]. Error: %s", ref, err)
		}
	}()

	writer, err := createFileInAllowedRoot(localPath, allowedDirectoriesForFilePaths(AllowedDirectories, localPath))
	if err != nil {
		return err
	}
	defer func() {
		if err := writer.Close(); err != nil {
			logger.Errorf(ctx, "failed to close File write stream at path [%s]. Error: %s", localPath, err)
		}
	}()

	if _, err := io.Copy(writer, reader); err != nil {
		return errors.Wrapf(err, "failed to write remote data to local filesystem at path [%s]", localPath)
	}
	return nil
}

// Downloads data from the given HTTP URL. If context is canceled then the request will be canceled.
func DownloadFileFromHTTP(ctx context.Context, ref storage.DataReference) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.String(), nil)
	if err != nil {
		logger.Errorf(ctx, "failed to create new http request with context, %s", err)
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to download from url :%s", ref)
	}
	return resp.Body, nil
}

func ValidatePath(path string, allowedDirectories []string) error {
	cleanPath := filepath.Clean(path)
	for _, dir := range allowedDirectories {
		cleanDir := filepath.Clean(dir)
		rel, err := filepath.Rel(cleanDir, cleanPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		return nil
	}
	return errors.Errorf("path does not start with an allowed prefix, path: %s", cleanPath)
}
