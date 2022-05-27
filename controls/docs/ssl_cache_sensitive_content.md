## Description

Verify that all sensitive information forms have disabled client-side caching, including autocomplete features. Browsers store page resources for two purposes: history and caching. The history allows users to return to a previously viewed page quickly, while caching is used to improve performance. Any content stored inside the cache can be viewed later by examining the browser's cache. One can avoid this privacy threat by adding a few `cache-control` headers to each webpage.
Pages containing sensitive information should include a `cache-control` header to ensure that the contents are not cached. It is recommended that the `cache-control` header should be configured as below:

```shell
Cache-Control: max-age=0, private, must-revalidate
```

- The `max-age` option indicates how long a response can be cached, and setting it to "0" will prevent caching.
- The `private` option will prevent proxies from caching the page.
- The `must-re-validate` option will prevent showing sensitive data when using the `Back` button.
