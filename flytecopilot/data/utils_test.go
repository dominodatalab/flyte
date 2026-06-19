package data

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flyteorg/flyte/flytestdlib/promutils"
	"github.com/flyteorg/flyte/flytestdlib/promutils/labeled"
	"github.com/flyteorg/flyte/flytestdlib/storage"
)

func TestIsFileReadable(t *testing.T) {
	tmpFolderLocation := ""
	tmpPrefix := "util_test"

	tmpDir, err := os.MkdirTemp(tmpFolderLocation, tmpPrefix)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tmpDir))
	}()
	p := path.Join(tmpDir, "x")
	f, i, err := IsFileReadable(p, false)
	assert.Error(t, err)
	assert.Empty(t, f)
	assert.Nil(t, i)

	assert.NoError(t, os.WriteFile(p, []byte("data"), os.ModePerm)) // #nosec G306
	f, i, err = IsFileReadable(p, false)
	assert.NoError(t, err)
	assert.Equal(t, p, f)
	assert.NotNil(t, i)
	assert.Equal(t, p, f)

	noExt := path.Join(tmpDir, "y")
	p = path.Join(tmpDir, "y.png")
	_, _, err = IsFileReadable(noExt, false)
	assert.Error(t, err)

	assert.NoError(t, os.WriteFile(p, []byte("data"), os.ModePerm)) // #nosec G306
	_, _, err = IsFileReadable(noExt, false)
	assert.Error(t, err)

	f, i, err = IsFileReadable(noExt, true)
	assert.NoError(t, err)
	assert.Equal(t, p, f)
	assert.NotNil(t, i)
	assert.Equal(t, p, f)
}

func TestUploadFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "util_test")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tmpDir))
	}()

	allowedRoot := path.Join(tmpDir, "allowed")
	assert.NoError(t, os.MkdirAll(allowedRoot, os.ModePerm))
	oldAllowed := AllowedDirectories
	AllowedDirectories = []string{allowedRoot}
	defer func() { AllowedDirectories = oldAllowed }()

	exist := path.Join(allowedRoot, "exist-file")
	data := []byte("data")
	l := int64(len(data))
	assert.NoError(t, os.WriteFile(exist, data, os.ModePerm)) // #nosec G306

	outsideFile := path.Join(tmpDir, "outside", "secret-file")
	assert.NoError(t, os.MkdirAll(path.Dir(outsideFile), os.ModePerm))
	assert.NoError(t, os.WriteFile(outsideFile, data, os.ModePerm)) // #nosec G306
	symlinkRelPath := "escape-link"
	assert.NoError(t, os.Symlink(outsideFile, path.Join(allowedRoot, symlinkRelPath)))

	store, err := storage.NewDataStore(&storage.Config{Type: storage.TypeMemory}, promutils.NewTestScope())
	assert.NoError(t, err)

	ctx := context.TODO()
	assert.NoError(t, UploadFileToStorage(ctx, allowedRoot, "exist-file", "exist", l, store))
	m, err := store.Head(ctx, "exist")
	assert.True(t, m.Exists())
	assert.NoError(t, err)

	assert.Error(t, UploadFileToStorage(ctx, allowedRoot, "non-exist-file", "nonExist", l, store))
	// symlink appears under allowedRoot but resolves outside it; OpenInRoot must reject this
	assert.Error(t, UploadFileToStorage(ctx, allowedRoot, symlinkRelPath, "disallowed", l, store))
}

func TestDownloadFromHttp(t *testing.T) {
	loc := storage.DataReference("https://raw.githubusercontent.com/flyteorg/flyte/master/README.md")
	badLoc := storage.DataReference("https://no-exist")
	f, err := DownloadFileFromHTTP(context.TODO(), loc)
	if assert.NoError(t, err) {
		if assert.NotNil(t, f) {
			f.Close()
		}
	}

	_, err = DownloadFileFromHTTP(context.TODO(), badLoc)
	assert.Error(t, err)
}

func TestDownloadFromStorage(t *testing.T) {
	store, err := storage.NewDataStore(&storage.Config{Type: storage.TypeMemory}, promutils.NewTestScope())
	assert.NoError(t, err)
	ref := storage.DataReference("ref")

	f, err := DownloadFileFromStorage(context.TODO(), ref, store)
	assert.Error(t, err)
	assert.Nil(t, f)

	data := []byte("data")
	l := int64(len(data))

	assert.NoError(t, store.WriteRaw(context.TODO(), ref, l, storage.Options{}, bytes.NewReader(data)))
	f, err = DownloadFileFromStorage(context.TODO(), ref, store)
	if assert.NoError(t, err) {
		assert.NotNil(t, f)
		f.Close()
	}
}

func TestValidatePath(t *testing.T) {
	tmpFolderLocation := ""
	tmpPrefix := "util_test"

	tmpDir, err := os.MkdirTemp(tmpFolderLocation, tmpPrefix)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tmpDir))
	}()

	for name, tt := range map[string]struct {
		path        string
		expectedErr error
	}{
		"Valid simple file path": {
			path: tmpDir + "/events.csv",
		},
		"Invalid protected path": {
			path:        "/etc/shadow",
			expectedErr: errors.New("path does not start with an allowed prefix"),
		},
		"Invalid protected path references location outside of the root": {
			path:        tmpDir + "/../etc/shadow",
			expectedErr: errors.New("path does not start with an allowed prefix"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidatePath(tt.path, []string{tmpDir})
			if tt.expectedErr != nil {
				assert.ErrorContains(t, err, tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func init() {
	labeled.SetMetricKeys("test")
}
