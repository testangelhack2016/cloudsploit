# AWS Audit Manager Plugins Documentation

This document provides a comprehensive overview of the AWS Audit Manager plugins within the CloudSploit system.

## Architecture Overview

The Audit Manager plugins are part of the AWS plugin suite for CloudSploit. They are designed to integrate with the core scanning engine (`engine.js`) to assess the configuration and security of AWS Audit Manager. The architecture follows the standard CloudSploit plugin pattern, where collectors gather data from AWS, and plugins analyze that data to identify potential security risks.

The primary plugin for Audit Manager is:
1.  **`auditManagerEnabled.js`**: This plugin checks if AWS Audit Manager is enabled in the account.

This plugin is executed by the `engine.js` after the relevant data has been collected by the AWS collectors. The results are then passed to the post-processing modules for suppression and output formatting.

```mermaid
graph TD
    A[engine.js] --> B{AWS Collectors};
    B --> C{AWS Audit Manager Data};
    C --> D{Audit Manager Plugins};
    subgraph Audit Manager Plugins
        direction LR
        E[auditManagerEnabled.js]
    end
    D --> E;
    E --> F{Results};
    F --> G[Post-processors];
```

## Use Cases

### Use Case 1: Ensure Audit Manager is Enabled
- **User Interaction:** The user runs a scan on their AWS account.
- **System Process:**
    - The `auditManagerEnabled.js` plugin is executed.
    - It checks if Audit Manager is enabled in the current region.
    - If Audit Manager is not enabled, it generates a "FAIL" result.
- **Expected Outcome:** The user is alerted that Audit Manager is not enabled, which is a missed opportunity for continuous compliance and audit automation.

## System Diagrams

### Sequence Diagram: Audit Manager Scan

```mermaid
sequenceDiagram
    participant engine as engine.js
    participant collectors as AWS Collectors
    participant plugins as Audit Manager Plugins
    participant output as output.js

    engine->>collectors: Run collectors
    collectors->>plugins: Provide Audit Manager data
    plugins->>plugins: Analyze data to check if Audit Manager is enabled
    plugins-->>engine: Return results (OK/FAIL)
    engine->>output: Process and format results
    output-->>engine: Formatted report
```

## Technology Stack

-   **Programming Language:** Node.js
-   **Framework:** CloudSploit (custom plugin architecture)
-   **AWS SDK:** Used by the collectors to interact with the AWS API and retrieve Audit Manager data.

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
