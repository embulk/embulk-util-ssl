Embulk Utilities for SSL/TLS
=============================

SSL/TLS-related utility classes that are spinned off from [embulk-input-ftp](https://github.com/embulk/embulk-input-ftp).

For Embulk plugin developers
-----------------------------

* [Javadoc](https://dev.embulk.org/embulk-util-ssl/)

For Maintainers
----------------

### Release

Modify `version` in `build.gradle` at a detached commit, and then tag the commit with an annotation.

```
git checkout --detach master

(Edit: Remove "-SNAPSHOT" in "version" in build.gradle.)

git add build.gradle

git commit -m "Release vX.Y.Z"

git tag -a vX.Y.Z

(Edit: Write a tag annotation in the changelog format.)
```

See [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) for the changelog format. We adopt a part of it for Git's tag annotation like below.

```
## [X.Y.Z] - YYYY-MM-DD

### Added
- Added a feature.

### Changed
- Changed something.

### Fixed
- Fixed a bug.
```

Push the annotated tag, then. It triggers a release operation on GitHub Actions after approval.

```
git push -u origin vX.Y.Z
```
