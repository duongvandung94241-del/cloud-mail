import app from './hono/webs';
import { email } from './email/email';
import userService from './service/user-service';
import verifyRecordService from './service/verify-record-service';
import emailService from './service/email-service';
import kvObjService from './service/kv-obj-service';
import oauthService from "./service/oauth-service";
import analysisService from './service/analysis-service';

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // 1. Resend Inbound Webhook 路由（支持多别名穿透与数字验证码自动提取）
    if (url.pathname === '/webhook/resend' && req.method === 'POST') {
      try {
        const payload = await req.json();
        const eventData = payload.data || payload;
        const emailId = eventData.email_id || payload.email_id;
        const rawTo = eventData.to?.[0] || payload.to?.[0] || '';
        const toAddress = rawTo.toLowerCase().trim();
        const fromAddress = eventData.from || payload.from || 'unknown';
        const subject = eventData.subject || payload.subject || '';

        if (!toAddress) {
          return Response.json({ code: 400, message: 'Missing recipient' }, { status: 400 });
        }

        const apiKey = env.RESEND_API_KEY;
        let content = '';
        let originalTo = '';

        if (emailId && apiKey) {
          try {
            const res = await fetch(`https://api.resend.com/emails/receiving/${emailId}`, {
              headers: { 
                'Authorization': `Bearer ${apiKey}`,
                'User-Agent': 'Cloudflare-Worker-Acloud-Mail'
              }
            });
            if (res.ok) {
              const detail = await res.json();
              content = detail.text || detail.html || '';

              // 从原始邮件 headers 中解析原始收件人
              if (Array.isArray(detail.headers)) {
                const toHeader = detail.headers.find(h => h.name?.toLowerCase() === 'to');
                if (toHeader) originalTo = toHeader.value;
              } else if (detail.headers?.to) {
                originalTo = detail.headers.to;
              }
            } else {
              console.error(`Fetch Resend email failed: ${res.status}`);
            }
          } catch (err) {
            console.error('Fetch Resend detail error:', err);
          }
        }

        // 正则提取 4~8 位数字验证码（优先提取常见 6 位）
        const match = content.match(/(?:code|verification|otp|pin|验证码)[\s\S]{0,30}?(\b\d{4,8}\b)/i) 
                   || content.match(/\b\d{6}\b/)
                   || subject.match(/\b\d{6}\b/);
        const code = match ? (match[1] || match[0]) : null;

        // 收集所有需要关联绑定的邮箱地址
        const targetKeys = new Set([toAddress]);

        // 1. 若 headers 中提取出原始收件人
        if (originalTo) {
          const extractedOriginal = originalTo.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
          if (extractedOriginal) targetKeys.add(extractedOriginal[0].toLowerCase().trim());
        }

        // 2. 从邮件正文中兜底提取包含的 @icloud.com 邮箱
        const icloudMatch = content.match(/[a-zA-Z0-9._%+-]+@icloud\.com/i);
        if (icloudMatch) {
          targetKeys.add(icloudMatch[0].toLowerCase().trim());
        }

        // 批量存入 KV
        if (env.kv && code) {
          for (const emailKey of targetKeys) {
            await env.kv.put(`otp:${emailKey}`, code, { expirationTtl: 600 });
            await env.kv.put(`raw:${emailKey}`, content.slice(0, 1000), { expirationTtl: 600 });
          }
        }

        // 存入 D1 数据库维持后台面板收件记录
        if (env.db) {
          try {
            const emailUuid = crypto.randomUUID();
            const now = Math.floor(Date.now() / 1000);
            await env.db.prepare(
              `INSERT INTO emails (id, to_address, from_address, subject, content, code, is_read, is_deleted, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`
            ).bind(
              emailUuid,
              toAddress,
              fromAddress,
              subject,
              content,
              code,
              now,
              now
            ).run();
          } catch (dbErr) {
            console.error('D1 insert error:', dbErr);
          }
        }

        return Response.json({ code: 200, status: 'success', extracted_code: code, mapped_keys: Array.from(targetKeys) });
      } catch (err) {
        console.error('Webhook execution failed:', err);
        return Response.json({ code: 500, error: err.message }, { status: 500 });
      }
    }

    // 2. 自动化脚本 /m 极速轮询取码接口（毫秒级响应纯文本验证码）
    if (url.pathname === '/m') {
      const emailParam = (url.searchParams.get('e') || '').toLowerCase().trim();
      if (!emailParam) return new Response('Missing ?e= parameter', { status: 400 });
      const code = env.kv ? await env.kv.get(`otp:${emailParam}`) : null;
      return new Response(code || 'WAITING', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 原有系统路由与鉴权逻辑
    if (url.pathname.startsWith('/api/')) {
      url.pathname = url.pathname.replace('/api', '');
      req = new Request(url.toString(), req);
      return app.fetch(req, env, ctx);
    }

    if (['/static/','/attachments/'].some(p => url.pathname.startsWith(p))) {
      return await kvObjService.toObjResp({ env }, url.pathname.substring(1));
    }

    return env.assets.fetch(req);
  },
  email: email,
  async scheduled(c, env, ctx) {
    if (c.cron === '*/30 * * * *') {
      await analysisService.refreshEchartsCache({ env });
      return;
    }

    await verifyRecordService.clearRecord({ env });
    await userService.resetDaySendCount({ env });
    await emailService.completeReceiveAll({ env });
    await oauthService.clearNoBindOathUser({ env });
    await analysisService.refreshEchartsCache({ env });
  },
};
