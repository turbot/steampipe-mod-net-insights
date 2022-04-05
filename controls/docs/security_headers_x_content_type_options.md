## Description

X-Content-Type-Options header with the `nosniff` value helps protect against mime type sniffing. Mime type sniffing attacks are only effective in specific scenarios where they cause the browser to interpret text or binary content as HTML. For example, if a user uploads an avatar file named `xss.html` and the web application does not set a Content-type header when serving the image, the browser will try to determine the content type and will likely treat `xss.html` as an HTML file. The attacker can then direct users to `xss.html` and conduct a Cross-Site Scripting attack.
