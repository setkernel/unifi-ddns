class BadRequestException extends Error {
	constructor(reason) {
		super(reason);
		this.status = 400;
		this.statusText = "Bad Request";
	}
}

class CloudflareApiException extends Error {
	constructor(reason) {
		super(reason);
		this.status = 500;
		this.statusText = "Internal Server Error";
	}
}

class Cloudflare {
	constructor(options) {
		this.cloudflare_url = "https://api.cloudflare.com/client/v4";
		this.token = options.token;
	}

	async findZone(name) {
		const response = await this._fetchWithToken(`zones?name=${name}`);
		const body = await response.json();
		if (!body.success || body.result.length === 0) {
			throw new CloudflareApiException(`Failed to find zone '${name}'`);
		}
		return body.result[0];
	}

	async findRecord(zone, name, isIPV4 = true) {
		const rrType = isIPV4 ? "A" : "AAAA";
		const response = await this._fetchWithToken(`zones/${zone.id}/dns_records?name=${name}`);
		const body = await response.json();
		if (!body.success || body.result.length === 0) {
			throw new CloudflareApiException(`Failed to find DNS record '${name}'`);
		}
		return body.result.find(rr => rr.type === rrType);
	}

	async updateRecord(record, value) {
		record.content = value;
		const response = await this._fetchWithToken(
			`zones/${record.zone_id}/dns_records/${record.id}`,
			{
				method: "PUT",
				body: JSON.stringify(record),
			}
		);
		const body = await response.json();
		if (!body.success) {
			throw new CloudflareApiException("Failed to update DNS record");
		}
		return body.result;
	}

	async _fetchWithToken(endpoint, options = {}) {
		const url = `${this.cloudflare_url}/${endpoint}`;
		options.headers = {
			"Content-Type": "application/json",
			Authorization: `Bearer ${this.token}`,
			...options.headers,
		};
		const response = await fetch(url, options);
		if (!response.ok) {
			throw new CloudflareApiException(`API Request failed with status ${response.status}`);
		}
		return response;
	}
}

function requireHttps(request) {
	const { protocol } = new URL(request.url);
	const forwardedProtocol = request.headers.get("x-forwarded-proto");
	if (protocol !== "https:" || forwardedProtocol !== "https") {
		throw new BadRequestException("Please use a HTTPS connection.");
	}
}

function parseBasicAuth(request) {
	const authorization = request.headers.get("Authorization");
	if (!authorization) return {};

	const [, data] = authorization.split(" ");
	if (!data) throw new BadRequestException("Invalid authorization value.");

	const decoded = atob(data);
	const [username, password] = decoded.split(":");
	if (!username || !password) {
		throw new BadRequestException("Invalid username or password.");
	}

	return { username, password };
}

async function handleRequest(request) {
	requireHttps(request);
	const { pathname, searchParams } = new URL(request.url);

	if (pathname === "/favicon.ico" || pathname === "/robots.txt") {
		return new Response(null, { status: 204 });
	}

	if (!pathname.endsWith("/update")) {
		return new Response("Not Found.", { status: 404 });
	}

	const { username, password } = parseBasicAuth(request);
	const token = password || searchParams.get("token");
	const hostnames = (searchParams.get("hostname") || searchParams.get("domains"))?.split(",");
	const ips = (searchParams.get("myip") || searchParams.get("ip"))?.split(",") || [request.headers.get("Cf-Connecting-Ip")];

	if (!hostnames || !ips) {
		throw new BadRequestException("You must specify both hostname(s) and IP address(es).");
	}

	await Promise.all(ips.map(ip => informAPI(hostnames, ip.trim(), username, token)));

	return new Response("good", {
		status: 200,
		headers: {
			"Content-Type": "text/plain;charset=UTF-8",
			"Cache-Control": "no-store",
		},
	});
}

async function informAPI(hostnames, ip, name, token) {
	const cloudflare = new Cloudflare({ token });
	const isIPV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip); // Better IPv4 validation
	const zones = new Map();

	await Promise.all(hostnames.map(async hostname => {
		const domainName = hostname.split(".").slice(-2).join(".");
		if (!zones.has(domainName)) {
			zones.set(domainName, await cloudflare.findZone(domainName));
		}

		const zone = zones.get(domainName);
		const record = await cloudflare.findRecord(zone, hostname, isIPV4);
		if (record) {
			await cloudflare.updateRecord(record, ip);
		}
	}));
}

export default {
	async fetch(request) {
		return handleRequest(request).catch(err => {
			console.error(err);
			const message = err.reason || err.stack || "Unknown Error";
			return new Response(message, {
				status: err.status || 500,
				headers: {
					"Content-Type": "text/plain;charset=UTF-8",
					"Cache-Control": "no-store",
				},
			});
		});
	},
};
