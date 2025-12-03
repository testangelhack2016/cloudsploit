#!/bin/bash

# Exit on any error
set -e

# Create the directory for extracted plugins if it doesn't exist
mkdir -p extracted_plugins/aws

# Run the script to extract plugin information for AWS
./extract_plugin_info.sh aws

# Define the output file and temporary build files
DOC_FILE="_docs/aws_architecture.md"
JSON_BUILD_FILE=$(mktemp -p _docs)

# Overwrite the document with the standard header
cat << 'EOF' > "$DOC_FILE"
# AWS Architecture Documentation

This document provides a comprehensive overview of the AWS resources used in this project, including their metadata and architecture diagrams.

## High-Level System Overview

The system is designed to scan and monitor AWS environments for security misconfigurations. It leverages various AWS services to collect data, analyze it, and provide actionable insights.

## Use Cases

*   **Continuous Security Monitoring:** Regularly scan AWS accounts to identify and remediate security vulnerabilities.
*   **Compliance Auditing:** Ensure that the AWS environment complies with industry standards and best practices.
*   **On-Demand Security Scans:** Perform security scans on-demand to assess the security posture of specific resources.

## Data Flow Diagram

```mermaid
graph TD
    A[Users] --> B{CloudSploit Aqua Engine};
    B --> C[AWS API];
    C --> D[AWS Services];
    D --> E[Security Scan Results];
    E --> B;
    B --> F[Output];
```

## Mermaid Diagram

```mermaid
graph TD
    subgraph "AWS Environment"
        direction LR
        A[EC2 Instances]
        B[S3 Buckets]
        C[RDS Databases]
        D[IAM Roles]
    end

    subgraph "CloudSploit"
        direction LR
        E[Collector] --> F[Analyzer];
        F --> G[Report Generator];
    end

    A --> E;
    B --> E;
    C --> E;
    D --> E;

    G --> H[Security Reports];
```

## AWS Plugin Metadata
EOF

# Process each plugin and append its metadata to the document
find extracted_plugins/aws -name "*_metadata.json" | sort | while read -r meta_file; do
    plugin_name=$(basename "$meta_file" _metadata.json)
    service_dir=$(dirname "$meta_file" | xargs basename)
    js_file="plugins/aws/${service_dir}/${plugin_name}.js"

    # Add a new section for the plugin
    echo "" >> "$DOC_FILE"
    echo "### \`$(basename "$meta_file")\`" >> "$DOC_FILE"
    echo "" >> "$DOC_FILE"
    echo "\`\`\`json" >> "$DOC_FILE"

    # Clear the temporary JSON build file
    > "$JSON_BUILD_FILE"

    # Extract metadata from the JSON file
    if [ -s "$meta_file" ]; then
        sed '1d;$d' "$meta_file" >> "$JSON_BUILD_FILE"
    fi

    # Extract additional metadata from the JS file
    if [ -f "$js_file" ]; then
        domain=$(grep -E "^\s*domain:" "$js_file" | sed -n "s/.*domain: *'\\([^']+\\)'.*/  \\\"domain\\\": \\\"\\1\\\",/p")
        if [ -n "$domain" ]; then echo "$domain" >> "$JSON_BUILD_FILE"; fi

        severity=$(grep -E "^\s*severity:" "$js_file" | sed -n "s/.*severity: *'\\([^']+\\)'.*/  \\\"severity\\\": \\\"\\1\\\",/p")
        if [ -n "$severity" ]; then echo "$severity" >> "$JSON_BUILD_FILE"; fi

        apis=$(grep -E "^\s*apis:" "$js_file" | sed -n "s/.*apis: *\\(\\[.*\\]\\).*/  \\\"apis\\\": \\1,/p" | sed "s/'/\\\"/g")
        if [ -n "$apis" ]; then echo "$apis" >> "$JSON_BUILD_FILE"; fi

        rules=$(grep "realtime_triggers:" "$js_file" | sed -n "s/.*realtime_triggers: *\\(\\[.*\\]\\).*/  \\\"rules\\\": \\1,/p" | sed "s/'/\\\"/g")
        if [ -n "$rules" ]; then echo "$rules" >> "$JSON_BUILD_FILE"; fi
    fi

    # Finalize the JSON content and append it to the document
    echo "{" >> "$DOC_FILE"
    sed '$s/,$//' "$JSON_BUILD_FILE" >> "$DOC_FILE"
    echo "}" >> "$DOC_FILE"

    echo "\`\`\`" >> "$DOC_FILE"
done

# Clean up the temporary build file
rm "$JSON_BUILD_FILE"
