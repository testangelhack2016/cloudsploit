#!/bin/bash

# Exit on any error
set -ex

# Ensure the extract_plugin_info.sh script is executable
if [ -f "extract_plugin_info.sh" ]; then
    chmod +x extract_plugin_info.sh
else
    echo "Error: extract_plugin_info.sh not found!"
    exit 1
fi

# Create the output directory
EXTRACTED_PLUGINS_DIR="_docs/extracted_plugins"
mkdir -p "$EXTRACTED_PLUGINS_DIR/aws"

# Run the extraction script
./extract_plugin_info.sh aws "$EXTRACTED_PLUGINS_DIR"

# Verify that the files were created
echo "Extraction complete. Verifying output..."
ls -l "$EXTRACTED_PLUGINS_DIR/aws"
