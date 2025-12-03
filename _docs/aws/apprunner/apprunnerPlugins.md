# AWS App Runner Plugins Documentation

This document provides a comprehensive overview of the AWS App Runner plugins within the CloudSploit system.

## Architecture Overview

The App Runner plugins are part of the AWS plugin suite for CloudSploit. They are designed to integrate with the core scanning engine (`engine.js`) to assess the configuration and security of AWS App Runner services. The architecture follows the standard CloudSploit plugin pattern, where collectors gather data from AWS, and plugins analyze that data to identify potential security risks.

The primary plugin for App Runner is:
1.  **`serviceEncrypted.js`**: This plugin checks if the App Runner service is encrypted using a customer-managed KMS key.

This plugin is executed by the `engine.js` after the relevant data has been collected by the AWS collectors. The results are then passed to the post-processing modules for suppression and output formatting.

```mermaid
graph TD
    A[engine.js] --> B{AWS Collectors};
    B --> C{AWS App Runner Data};
    C --> D{App Runner Plugins};
    subgraph App Runner Plugins
        direction LR
        E[serviceEncrypted.js]
    end
    D --> E;
    E --> F{Results};
    F --> G[Post-processors];
```

## Use Cases

### Use Case 1: Ensure App Runner Service is Encrypted
- **User Interaction:** The user runs a scan on their AWS account.
- **System Process:**
    - The `serviceEncrypted.js` plugin is executed.
    - It inspects each App Runner service to determine if it's configured with a customer-managed KMS key for encryption.
    - If a service is not encrypted with a KMS CMK, it generates a "FAIL" result.
- **Expected Outcome:** The user is alerted to any App Runner services that are not using customer-managed keys for encryption, allowing them to enhance their data protection posture.

## System Diagrams

### Sequence Diagram: App Runner Scan

```mermaid
sequenceDiagram
    participant engine as engine.js
    participant collectors as AWS Collectors
    participant plugins as App Runner Plugins
    participant output as output.js

    engine->>collectors: Run collectors
    collectors->>plugins: Provide App Runner data
    plugins->>plugins: Analyze data for encryption status
    plugins-->>engine: Return results (OK/FAIL)
    engine->>output: Process and format results
    output-->>engine: Formatted report
```

## Technology Stack

-   **Programming Language:** Node.js
-   **Framework:** CloudSploit (custom plugin architecture)
-   **AWS SDK:** Used by the collectors to interact with the AWS API and retrieve App Runner data.

## Plugin Interface and Finding Structure

This section details the standard interface for all CloudSploit plugins and the structure of the findings they generate.

### Plugin Module Exports

Each plugin is a Node.js module that exports a standard set of properties and a `run` function.

```mermaid
classDiagram
    class Plugin {
        +String title
        +String category
        +String description
        +String more_info
        +String link
        +String recommended_action
        +run(collection, settings, callback)
    }
```

### The `run` Function

The `run` function is the entry point for the plugin's execution.

`run(collection, settings, callback)`

-   **Parameters:**
    -   `collection` (object): An object containing all the data gathered by the collectors.
    -   `settings` (object): An object containing global settings for the scan.
    -   `callback` (function): A standard Node.js callback function `(err, results)`.

### Finding (Result) Structure

The `run` function passes an array of "finding" objects to its callback.

```mermaid
classDiagram
    class Finding {
        +Integer status
        +String message
        +String resource
        +String region
    }
    class Status {
        <<Enumeration>>
        OK (0)
        WARN (1)
        FAIL (2)
    }
    Finding -- Status
```
