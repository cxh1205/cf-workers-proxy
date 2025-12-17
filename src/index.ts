import { env } from 'cloudflare:workers';
import * as z from "zod";

// 1. 修改辅助函数：兼容 "已经是对象" 和 "需要解析的字符串" 两种情况
const flexibleJson = <T extends z.ZodTypeAny>(schema: T) => {
	return z.preprocess((val, ctx) => {
		// 情况 A: 已经是对象/数组 (来自 wrangler.jsonc / 单元测试对象)
		if (typeof val === 'object' && val !== null) {
			return val;
		}

		// 情况 B: 字符串 (来自 .env)
		if (typeof val === 'string') {
			if (val.trim() === '') return undefined;
			try {
				return JSON.parse(val);
			} catch (e) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "Invalid JSON string format",
					fatal: true // 标记为致命错误，停止后续校验
				});
				return z.NEVER;
			}
		}

		// 情况 C: undefined/null
		return val;
	}, schema);
};

// 2. Schema 定义
const ConfigSchema = z.object({
	ENVIRONMENT:z.enum(['production', 'development', 'staging']).default('production'),
	PASSWORD: z.string().default(''),
	PROXY_HOSTNAME: z.string().min(1, "PROXY_HOSTNAME is required"),
	PROXY_PROTOCOL: z.string().optional().default('https://'),
	// 兼容 String 或 Array<String>
	PROXY_RESOURCE_DOMAINS: flexibleJson(z.array(z.string()))
		.default([]),

	// 兼容 String 或 Record<String, String>
	PROXY_DOMAINS: flexibleJson(z.record(z.string(), z.string()))
		.default({}),

	// -----------------------------

	WECHAT_CHECK_FILE_NAME: z.string().optional(),
	WECHAT_CHECK_FILE_CONTENT: z.string().optional(),
	WECHAT_CHECK_FILE_MODIFY_TIME: z.string().optional(),
});

const result = ConfigSchema.safeParse(env);

if (!result.success) {
	// 如果校验失败，返回详细的错误信息，方便调试
	throw new Error(`Configuration validation failed. Please check the logs for details. ${JSON.stringify(result.error.format(), null, 2)}`);
}

// 获取清洗后的 config
const config = result.data;


const CONFIG = {
	...config,
	PASSWORD_COOKIE_NAME: 'xx-worker-password',

	// 需要移除的请求头
	REMOVE_HEADERS: [
		'sec-fetch-dest',
		'sec-fetch-mode',
		'sec-fetch-site',
		'sec-fetch-user',
		'content-security-policy',
		'content-security-policy-report-only',
		'location',
	],

	// 伪装的浏览器标识
	USER_AGENT_HEADERS: {
		// 'sec-ch-ua-platform': '"Windows"',
		// 'sec-ch-ua-mobile': '?0',
		// 'sec-ch-ua': '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"'
	} as Record<string, string>,
};

/**
 * 全局 BaseURL
 */
let BASEURL: string = '';

export default {
	async fetch(request: Request, env: unknown, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// 1. 初始化配置 & 设置 BaseURL
		BASEURL = CONFIG.ENVIRONMENT === 'development' ? 'http://127.0.0.1:8787' : url.origin;

		if (
			CONFIG.WECHAT_CHECK_FILE_NAME &&
			CONFIG.WECHAT_CHECK_FILE_CONTENT &&
			CONFIG.WECHAT_CHECK_FILE_MODIFY_TIME &&
			url.pathname === `/${CONFIG.WECHAT_CHECK_FILE_NAME}`
		) {
			// 微信验证文件请求
			return new Response(CONFIG.WECHAT_CHECK_FILE_CONTENT, {
				status: 200,
				headers: {
					'Content-Type': 'text/plain; charset=utf-8',
					'Cache-Control': 'max-age=0',
					Server: 'nginx/1.27.5',
					Date: new Date().toUTCString(),
					'Last-Modified': CONFIG.WECHAT_CHECK_FILE_MODIFY_TIME,
					Connection: 'keep-alive',
				},
			});
		}

		// --- 鉴权模块开始 ---
		const authResponse = await handleAuthentication(request, url);
		if (authResponse) {
			// 如果 handleAuthentication 返回了 Response（比如登录页或重定向），直接返回，不走代理逻辑
			return authResponse;
		}
		// --- 鉴权模块结束 ---

		if (CONFIG.PROXY_HOSTNAME === '') {
			return new Response('Proxy Error: PROXY_HOSTNAME is not configured.', { status: 500 });
		}

		// 2. 解析目标 URL
		const targetUrlStr = parseTargetUrl(url);

		// 3. 构建请求对象
		const newRequest = new Request(targetUrlStr, {
			method: request.method,
			headers: request.headers, // 注意：这里的 headers 稍后会清理 Cookie
			body: request.body,
			redirect: 'manual',
		});

		// 4. 清理请求头
		CONFIG.REMOVE_HEADERS.forEach((h) => newRequest.headers.delete(h));

		// **关键步骤：移除鉴权 Cookie，防止发送给 GitHub**
		const cookieHeader = newRequest.headers.get('Cookie');
		if (cookieHeader) {
			// 使用正则移除我们的特定 cookie，保留其他可能存在的 cookie
			const cleanCookie = cookieHeader.replace(new RegExp(`(^|;\\s*)${CONFIG.PASSWORD_COOKIE_NAME}=[^;]*`), '').trim();
			if (cleanCookie) {
				newRequest.headers.set('Cookie', cleanCookie);
			} else {
				newRequest.headers.delete('Cookie');
			}
		}

		newRequest.headers.set('Host', CONFIG.PROXY_HOSTNAME);
		newRequest.headers.set('Origin', CONFIG.PROXY_PROTOCOL + CONFIG.PROXY_HOSTNAME);
		newRequest.headers.set('Referer', CONFIG.PROXY_PROTOCOL + CONFIG.PROXY_HOSTNAME + url.pathname);

		try {
			// 5. 发起请求
			let response = await fetch(newRequest);

			// 6. 准备响应头
			const newHeaders = processHeaders(response.headers);

			// 7. 特殊处理：重定向 (3xx)
			if (response.status >= 300 && response.status < 400) {
				const location = response.headers.get('location');
				if (location) {
					const rewrittenLocation = rewriteUrl(location);
					newHeaders.set('location', rewrittenLocation);
					return new Response(null, {
						status: response.status,
						statusText: response.statusText,
						headers: newHeaders,
					});
				}
			}

			// 8. 特殊处理：文本内容重写 (2xx)
			// 如果是文本类型 (HTML, JSON, JS)，需要重写内部链接
			let body;
			if (isTextType(response)) {
				const text = await response.text();
				body = rewriteBody(text);
			} else {
				// 非文本类型，直接返回原始 body (如图片、视频等)
				body = response.body;
			}

			// 9. 返回最终响应
			return new Response(body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		} catch (e) {
			const errorMessage = e instanceof Error ? e.message : String(e);
			return new Response(`Proxy Error: ${errorMessage}`, { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;

/**
 * --- 鉴权逻辑函数 ---
 * 如果验证通过返回 null，否则返回 Response (登录页或重定向)
 */
async function handleAuthentication(request: Request, url: URL): Promise<Response | null> {
	// 1. 如果没有配置密码，直接放行
	if (!CONFIG.PASSWORD) return null;

	const userAgent = request.headers.get('User-Agent') || '';

	// 2. Git 客户端白名单 (Git 操作直接放行)
	// 常见的 git user-agent 格式: "git/2.30.0", "git-lfs/2.13.0"
	const passUserAgents = ['git/', 'git-lfs/', 'curl/'];
	if (passUserAgents.some((ua) => userAgent.startsWith(ua))) {
		return null;
	}

	// 3. 检查 Cookie
	const cookies = request.headers.get('Cookie') || '';
	if (cookies.includes(`${CONFIG.PASSWORD_COOKIE_NAME}=${CONFIG.PASSWORD}`)) {
		return null; // Cookie 验证通过，放行
	}

	const targetUrl = new URL(url.toString().replace(url.origin, BASEURL));

	// 4. 处理登录请求 (POST)
	if (request.method === 'POST') {
		try {
			const formData = await request.formData();
			const inputPassword = formData.get('password');

			if (inputPassword === CONFIG.PASSWORD) {
				// 密码正确，设置 Cookie 并刷新页面
				return new Response(null, {
					status: 302,
					headers: {
						Location: targetUrl.href, // 刷新当前页
						'Set-Cookie': `${CONFIG.PASSWORD_COOKIE_NAME}=${CONFIG.PASSWORD}; Path=/; HttpOnly; Max-Age=31536000; SameSite=Lax`,
					},
				});
			} else {
				// 密码错误，显示错误提示
				return getLoginPage(targetUrl.href, '密码错误，请重试');
			}
		} catch (e) {
			// Form 解析失败等情况
		}
	}

	// 5. 默认：显示登录页面
	return getLoginPage(targetUrl.href);
}

/**
 * --- 登录页面 HTML 生成器 ---
 */
function getLoginPage(targetUrl: string, errorMsg: string = ''): Response {
	const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>访问验证</title>
        <style>
            :root {
                --primary-color: #0969da;
                --bg-color: #f6f8fa;
                --card-bg: #ffffff;
                --text-color: #24292f;
                --border-color: #d0d7de;
            }
            @media (prefers-color-scheme: dark) {
                :root {
                    --primary-color: #2f81f7;
                    --bg-color: #0d1117;
                    --card-bg: #161b22;
                    --text-color: #c9d1d9;
                    --border-color: #30363d;
                }
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                background-color: var(--bg-color);
                color: var(--text-color);
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
            }
            .login-card {
                background: var(--card-bg);
                padding: 2rem;
                border-radius: 6px;
                box-shadow: 0 3px 6px rgba(140, 149, 159, 0.15);
                border: 1px solid var(--border-color);
                width: 100%;
                max-width: 340px;
                text-align: center;
            }
            .logo {
                margin-bottom: 1.5rem;
                font-size: 24px;
                font-weight: 600;
            }
            input[type="password"] {
                width: 100%;
                padding: 8px 12px;
                margin-bottom: 1rem;
                border: 1px solid var(--border-color);
                border-radius: 6px;
                background: var(--bg-color);
                color: var(--text-color);
                font-size: 14px;
                box-sizing: border-box;
                outline: none;
            }
            input[type="password"]:focus {
                border-color: var(--primary-color);
                box-shadow: 0 0 0 3px rgba(9, 105, 218, 0.3);
            }
            button {
                width: 100%;
                background-color: var(--primary-color);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            button:hover {
                opacity: 0.9;
            }
            .error {
                color: #cf222e;
                font-size: 13px;
                margin-bottom: 1rem;
                text-align: left;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="logo">受限资源</div>
            <form method="POST" action="${targetUrl}">
                ${errorMsg ? `<div class="error">${errorMsg}</div>` : ''}
                <input type="password" name="password" placeholder="请输入访问密码" required autofocus>
                <button type="submit">登 录</button>
            </form>
        </div>
    </body>
    </html>
    `;
	return new Response(html, {
		headers: { 'Content-Type': 'text/html; charset=utf-8' },
	});
}

/**
 * --- 核心逻辑函数 (保持原样，略有辅助函数更新) ---
 */

function parseTargetUrl(requestUrl: URL): string {
	// 匹配路径中的 URL (支持被 encode 过的)
	// 匹配 /https://... 或 /https%3A%2F%2F...
	const match = requestUrl.pathname.match(/^\/((https?:\/\/.+)|(https%3A%2F%2F.+)|(http%3A%2F%2F.+))$/);
	if (match) {
		let target = match[1];
		try {
			if (target.includes('%2F')) {
				target = decodeURIComponent(target);
			}
		} catch (e) {
			/* ignore */
		}

		// 保留查询参数
		return `${target}${requestUrl.search}${requestUrl.hash}`;
	}

	// 如果没有匹配到 URL 路径，默认访问主页
	return `${CONFIG.PROXY_PROTOCOL}${CONFIG.PROXY_HOSTNAME}${requestUrl.pathname}${requestUrl.search}${requestUrl.hash}`;
}

// 统一处理响应头：CORS、安全头清理、伪装头添加
function processHeaders(originalHeaders: Headers): Headers {
	const headers = new Headers(originalHeaders);

	// 添加 CORS
	headers.set('Access-Control-Allow-Origin', '*');
	headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE, PATCH');
	headers.set('Access-Control-Allow-Headers', '*');
	headers.set('Vary', 'Origin');
	if (CONFIG.ENVIRONMENT === 'development') {
		headers.set('Cache-Control', '0, no-cache, no-store, must-revalidate');
	}

	// 添加浏览器伪装
	Object.entries(CONFIG.USER_AGENT_HEADERS).forEach(([k, v]) => headers.set(k, v));

	// 移除不必要的响应头
	CONFIG.REMOVE_HEADERS.forEach((h) => headers.delete(h));
	return headers;
}

// 检查响应是否为文本类型
function isTextType(res: Response): boolean {
	const contentType = (res.headers.get('content-type') || '').toLowerCase();
	return contentType.includes('text/') || contentType.includes('application/json') || contentType.includes('javascript');
}

// 重写单个 URL (用于 Location 头)
function rewriteUrl(originalUrl: string): string {
	try {
		const u = new URL(originalUrl);
		// 检查该域名是否在我们的代理资源列表中
		const shouldProxy = CONFIG.PROXY_RESOURCE_DOMAINS.some((domain) => u.hostname == domain);

		if (shouldProxy) {
			// 构造为: BASEURL/https://original-url
			return `${BASEURL}/${originalUrl}`;
		}

		// 如果是基础域名，则返回baseurl重写
		if (originalUrl.startsWith(`${CONFIG.PROXY_PROTOCOL}${CONFIG.PROXY_HOSTNAME}`)) {
			// 基础域名也需要重写
			return originalUrl.replace(`${CONFIG.PROXY_PROTOCOL}${CONFIG.PROXY_HOSTNAME}`, BASEURL);
		}

		// 检查是否在直接替换的域名映射中
		for (const [originalDomain, proxyDomain] of Object.entries(CONFIG.PROXY_DOMAINS)) {
			if (u.hostname === originalDomain) {
				return originalUrl.replace(originalDomain, proxyDomain);
			}
		}
		// 如果不是目标域名，直接返回原始地址 (或者是基于当前 BaseURL 的相对路径)
		return originalUrl;
	} catch (e) {
		return originalUrl;
	}
}

interface Boundary {
	left: string;
	right: string;
}

function generateRegExpWithBoundary(content: string, boundary: Boundary): RegExp {
	return new RegExp(`(?<=${boundary.left})(${content})(?=${boundary.right})`, 'gi');
}

// 重写响应体内容 (批量替换域名)
function rewriteBody(content: string): string {
	let newContent = content;

	const boundaries: Boundary[] = [
		{ left: '(["\'`])', right: '(\\1|/[^\\1]*?\\1)' }, // 引号包裹
		{ left: '\\(', right: '(\\)|/[^)]*?\\))' }, // ()
	];
	// 首先替换基础域名
	for (const boundary of boundaries) {
		const regex = generateRegExpWithBoundary(`${CONFIG.PROXY_PROTOCOL}${CONFIG.PROXY_HOSTNAME.replace(/\./g, '\\.')}`, boundary);
		newContent = newContent.replace(regex, BASEURL);
	}

	// 遍历配置的资源域名列表，进行正则替换
	// 目标：将 "https://example.com/..." 替换为 "BASEURL/https://example.com/..."
	for (const boundary of boundaries) {
		for (const domain of CONFIG.PROXY_RESOURCE_DOMAINS) {
			const regex = generateRegExpWithBoundary(`https?:\\/\\/${domain}.*?`, boundary);
			newContent = newContent.replace(regex, (match) => {
				return `${BASEURL}/${match}`;
			});
		}
	}

	// 遍历需要直接替换的域名映射，进行正则替换
	for (const boundary of boundaries) {
		for (const [originalDomain, proxyDomain] of Object.entries(CONFIG.PROXY_DOMAINS)) {
			const regex = generateRegExpWithBoundary(`https?:\\/\\/${originalDomain}.*?`, boundary);
			newContent = newContent.replace(regex, (match) => {
				return match.replace(originalDomain, proxyDomain);
			});
		}
	}

	return newContent;
}
