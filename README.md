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

## Examples

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/georgepsarakis/chi-api-key-auth/apikey"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	// By default, the following variable names are used for secrets:
	// - CHI_API_KEY
	// - CHI_API_KEY_READONLY
	// The Authorization/Bearer header scheme as a request secret provider.
	chiReadonlyOpts := apikey.NewReadonlyOptions()
	r.Group(func(r chi.Router) {
		r.Use(apikey.Authorize(chiReadonlyOpts))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	if err := http.ListenAndServe(":3000", r); err != nil {
		panic(err)
	}
}
```

Wrong authorization results in a response with 401 status code (default failure handler):

```
$ curl localhost:3000 --header 'Authorization: Bearer wrong-key'
2025/03/31 15:06:28 "GET http://localhost:3000/ HTTP/1.1" from [::1]:59751 - 401 0B in 21.583µs
```

A successfully authorized request:

```
$ curl localhost:3000 --header 'Authorization: Bearer test-api-key-auth'
2025/03/31 15:06:59 "GET http://localhost:3000/ HTTP/1.1" from [::1]:59755 - 200 7B in 12.125µs
```
