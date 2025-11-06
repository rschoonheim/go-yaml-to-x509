# Config Segments Examples

This directory contains example YAML files demonstrating the config segments feature.

## Simple Format Example

See `simple.yaml` - Direct certificate configuration without segments.

## Segments Format Examples

### Basic Segments (`basic-segments.yaml`)
Demonstrates defining reusable segments and merging them.

### Role-Based Segments (`role-based-segments.yaml`)
Shows how to create role-specific segments (web-server, code-signing, etc.).

### Multi-Certificate Configuration
Shows how to maintain multiple certificate configs with shared segments for consistency.

## Running Examples

```go
package main

import (
    "fmt"
    "log"
    "os"
    
    factory "go-x509-factory"
)

func main() {
    yamlData, err := os.ReadFile(".examples/basic-segments.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    cert, err := factory.X509FromYaml(yamlData)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Certificate CN: %s\n", cert.Subject.CommonName)
    fmt.Printf("Issuer CN: %s\n", cert.Issuer.CommonName)
}
```

