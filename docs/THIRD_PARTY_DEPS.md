# Third-Party Dependencies

This document lists the third-party modules and services used by CloudSploit.

## Third-Party Modules (NPM Packages)

The following is a list of third-party Node.js modules used in this project, as defined in the `package.json` file.

| Module | Description |
|---|---|
| `@alicloud/pop-core` | Alibaba Cloud SDK for Node.js. Used for making API requests to Alibaba Cloud services. |
| `@azure/data-tables` | Microsoft Azure Data Tables client library for JavaScript. |
| `@azure/storage-file-share` | Microsoft Azure Storage File Share client library for JavaScript. |
| `@azure/storage-queue` | Microsoft Azure Storage Queue client library for JavaScript. |
| `@azure/storage-blob` | Microsoft Azure Storage Blob client library for JavaScript. |
| `@octokit/auth-app` | GitHub App authentication strategy for Octokit. |
| `@octokit/request` | A light-weight wrapper around Fetch to make requests to GitHub's REST API. |
| `@octokit/rest` | A Node.js module that provides a simple way to interact with the GitHub REST API. |
| `ali-oss` | Alibaba Cloud OSS (Object Storage Service) SDK for Node.js. |
| `argparse` | A command-line parsing library for Node.js. |
| `async` | A utility module which provides straight-forward, powerful functions for working with asynchronous JavaScript. |
| `aws-sdk` | The official AWS SDK for Node.js. |
| `azure-storage` | Legacy Microsoft Azure Storage client library for Node.js. |
| `csv-write-stream` | A CSV encoder that is also a writable stream. |
| `fast-safe-stringify` | A safe and fast JSON stringify implementation. |
| `google-auth-library` | Google's officially supported Node.js client library for using OAuth 2.0 authorization and authentication with Google APIs. |
| `minimatch` | A minimal matching library for Node.js. It works by converting glob expressions into JavaScript `RegExp` objects. |
| `ms-rest-azure` | The MS Rest Azure package provides a client for making requests to Azure services. |
| `tty-table` | A library for creating tables in the terminal. |

## Third-Party Services

CloudSploit integrates with the following third-party cloud services to perform security scanning and analysis:

*   **AWS (Amazon Web Services):** Scans a wide range of AWS services for security misconfigurations.
*   **Azure:** Scans Microsoft Azure services for security best practice violations.
*   **GCP (Google Cloud Platform):** Scans Google Cloud services to identify potential security risks.
*   **Oracle Cloud (OCI):** Scans Oracle Cloud Infrastructure services for security misconfigurations.
*   **GitHub:** Scans GitHub organizations and repositories for security-related settings.
*   **Alibaba Cloud:** Scans Alibaba Cloud services for security best practices.
