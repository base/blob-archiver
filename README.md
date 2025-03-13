[![](https://github.com/base/blob-archiver/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/base/blob-archiver/actions/workflows/github-code-scanning/codeql)

# Blob Archiver
The Blob Archiver is a service to archive and allow querying of all historical blobs from the beacon chain. It consists 
of two components:

* **Archiver** - Tracks the beacon chain and writes blobs to a storage backend
* **API** - Implements the blob sidecars [API](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlobSidecars), which 
allows clients to retrieve blobs from the storage backend

### Storage
There are currently two supported storage options:

* On-disk storage - Blobs are written to disk in a directory
* S3 storage - Blobs are written to an S3 bucket (or compatible service)

You can control which storage backend is used by setting the `BLOB_API_DATA_STORE` and `BLOB_ARCHIVER_DATA_STORE` to 
either `file` or `s3`.

The `s3` backend will also work with (for example) Google Cloud Storage buckets (instructions [here](https://medium.com/google-cloud/using-google-cloud-storage-with-minio-object-storage-c994fe4aab6b)). 

### Data Validity
Currently, the archiver and api do not validate the beacon node's data. Therefore, it's important to either trust the 
Beacon node, or validate the data in the client. There is an open [issue](https://github.com/base/blob-archiver/issues/4) 
to add data validation to the archiver and api.

### Development
The `Makefile` contains a number of commands for development:

```sh
# Run the tests
make test
# Run the integration tests (will start a local S3 bucket)
make integration 

# Lint the project
make lint

# Build the project
make build

# Check all tests, formatting, building
make check
```

#### Run Locally
To run the project locally, you should first copy `.env.template` to `.env` and then modify the environment variables
to your beacon client and storage backend of choice. Then you can run the project with:

```sh
docker compose up
```

You can see a full list of configuration options by running:
```sh
# API
go run api/cmd/main.go

# Archiver
go run archiver/cmd/main.go

```
