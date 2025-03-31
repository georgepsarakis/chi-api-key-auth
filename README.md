# chi-api-key-auth

A [Chi](https://github.com/go-chi/chi) middleware for API Key-based authorization.

## Features

### Deprecation Policy

Key rotation support using limited validity for API Key values under deprecation.

### Support for read-only & read-write keys

The key scope can be differentiated based on well-known HTTP verbs,
or by explicitly defining the list of allowed HTTP methods.

### Secret Provider Abstraction

Secrets can be provided using environment variables, with configurable variable names.
The secret provider can be swapped with any implementation supporting the given interface.
