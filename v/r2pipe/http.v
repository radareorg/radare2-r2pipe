module r2pipe

import net.http
import net.urllib

struct HttpTransport {
	endpoint urllib.URL
	options  HttpOptions
	limit    int
}

fn new_http(target string, options HttpOptions, limit int) !Transport {
	if options.read_timeout <= 0 || options.write_timeout <= 0 {
		return error('r2pipe: HTTP timeouts must be positive')
	}
	mut endpoint := urllib.parse(target) or { return error('r2pipe: invalid HTTP endpoint') }
	if endpoint.scheme !in ['http', 'https'] || endpoint.hostname() == ''
		|| endpoint.fragment != '' || target.contains_any('\r\n\t ') {
		return error('r2pipe: expected an HTTP(S) endpoint without a fragment')
	}
	if user := endpoint.user {
		if user.username != '' || user.password_set {
			return error('r2pipe: set HTTP credentials in the Authorization header')
		}
	}
	// A base URL and an explicit /cmd endpoint both use the same command route.
	path := endpoint.escaped_path().trim_right('/')
	endpoint.set_path(if endpoint.path.trim_right('/').ends_with('/cmd') {
		path
	} else {
		path + '/cmd'
	})!
	return &HttpTransport{
		endpoint: endpoint
		options:  options
		limit:    limit
	}
}

fn (mut transport HttpTransport) exchange(command string) !string {
	mut url := transport.endpoint
	mut req := http.Request{
		header:                       transport.options.header
		read_timeout:                 transport.options.read_timeout
		write_timeout:                transport.options.write_timeout
		proxy:                        transport.options.proxy
		verify:                       transport.options.verify
		cert:                         transport.options.cert
		cert_key:                     transport.options.cert_key
		allow_redirect:               false
		disable_connection_reuse:     true
		max_total_decompressed_bytes: transport.limit
		max_retries:                  1 // A command may have already changed the session when the response fails.
	}
	if !req.header.contains(.cache_control) {
		req.add_header(.cache_control, 'no-store')
	}
	if transport.options.method == .post {
		req.method = .post
		req.data = command
		if !req.header.contains(.content_type) {
			req.add_header(.content_type, 'text/plain')
		}
	} else {
		// Escape URI delimiters as well as dot segments that proxies may normalize.
		encoded := match command {
			'.' { '%2E' }
			'..' { '%2E%2E' }
			else { urllib.query_escape(command).replace('+', '%20') }
		}
		url.set_path('${url.escaped_path()}/${encoded}')!
	}
	req.url = url.str()
	if transport.limit > 0 {
		req.user_ptr = &transport.limit
		req.on_progress_body = limit_http_body
		req.on_progress = limit_http_wire
	}
	response := req.do()!
	if response.status_code < 200 || response.status_code >= 300 {
		return error_with_code('r2pipe: HTTP status ${response.status_code}', response.status_code)
	}
	return response.body
}

fn limit_http_body(req &http.Request, _ []u8, received u64, expected u64, _ int) ! {
	limit := unsafe { *(&int(req.user_ptr)) }
	if received > u64(limit) || expected > u64(limit) {
		return error('r2pipe: HTTP response exceeds ${limit} bytes')
	}
}

fn limit_http_wire(req &http.Request, _ []u8, received u64) ! {
	limit := unsafe { u64(*(&int(req.user_ptr))) }
	// Bound incomplete headers and chunk framing as well as decoded data.
	if received > limit + limit / 4 + 64 * 1024 {
		return error('r2pipe: HTTP response exceeds the wire size limit')
	}
}

fn (mut transport HttpTransport) close() {}
