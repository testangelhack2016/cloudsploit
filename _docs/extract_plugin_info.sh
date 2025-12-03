#!/bin/bash
#
# This script extracts metadata and configuration dependencies for all CloudSploit plugins.
# It iterates through each plugin file, uses Node.js to parse it, and outputs the results
# into a structured directory.
#
# Output Structure:
#   extracted_plugins/
#   ├── aws/
#   │   ├── accessanalyzer/
#   │   │   ├── accessAnalyzerEnabled_metadata.json
#   │   │   ├── accessAnalyzerEnabled_config.json
#   │   │   └── ...
#   └── ...

set -e

OUTPUT_DIR="extracted_plugins"
echo "Starting plugin extraction. Output will be in the '$OUTPUT_DIR' directory."

# Clean up previous runs
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Find all plugin files, excluding test files (*.spec.js)
find plugins -type f -name "*.js" ! -name "*.spec.js" | while read -r plugin_file; do
    # Determine the output path from the plugin file path
    provider=$(echo "$plugin_file" | cut -d'/' -f2)
    category=$(echo "$plugin_file" | cut -d'/' -f3)
    filename=$(basename "$plugin_file" .js)
    
    mkdir -p "$OUTPUT_DIR/$provider/$category"
    
    METADATA_FILE="$OUTPUT_DIR/$provider/$category/${filename}_metadata.json"
    CONFIG_FILE="$OUTPUT_DIR/$provider/$category/${filename}_config.json"
    
    # Use Node.js to extract information from the plugin file.
    # We use require() to get the exported metadata and fs.readFileSync with a regex
    # to find the configuration dependencies (i.e., data from collectors).
    
    node -e '
        const fs = require("fs");
        const path = require("path");
        const pluginPath = path.resolve(process.argv[1]);

        try {
            // Extract Metadata using require()
            const plugin = require(pluginPath);
            const metadata = {
                title: plugin.title,
                category: plugin.category,
                description: plugin.description,
                more_info: plugin.more_info,
                link: plugin.link,
                recommended_action: plugin.recommended_action,
                cloud: plugin.cloud
            };
            console.log(JSON.stringify(metadata, null, 2));

            // Use a separator to distinguish metadata from config
            console.log("---SEPARATOR---");

            // Extract Configuration Dependencies by reading the file content
            const fileContent = fs.readFileSync(pluginPath, "utf-8");
            
            // Regex to find all occurrences of `collection.service.apiCall`
            const regex = /collection\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)/g;
            const dependencies = new Set();
            let match;

            while ((match = regex.exec(fileContent)) !== null) {
                // We capture the service and the api call, e.g., "accessanalyzer.listAnalyzers"
                dependencies.add(`${match[1]}.${match[2]}`);
            }

            const config = {
                dependencies: Array.from(dependencies)
            };
            console.log(JSON.stringify(config, null, 2));

        } catch (e) {
            // If require() or regex fails, log to stderr and continue
            console.error(`Could not process ${pluginPath}: ${e.message}`);
            // Output empty JSON to avoid bash errors and indicate failure
            console.log("{}");
            console.log("---SEPARATOR---");
            console.log("{}");
        }
    ' "$plugin_file" | (
        # Read from the pipe until the separator
        metadata_content=""
        while IFS= read -r line && [ "$line" != "---SEPARATOR---" ]; do
            metadata_content+="$line
"
        done
        echo -e "$metadata_content" > "$METADATA_FILE"
        
        # Read the rest of the pipe for the config
        config_content=$(cat)
        echo -e "$config_content" > "$CONFIG_FILE"
    )
done

echo "Plugin extraction complete."
