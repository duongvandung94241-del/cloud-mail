// Resend Inbound Webhook 路由：接收邮件、拉取正文、正则提取验证码入库与写入 KV
app.post('/api/webhook/resend', async (c) => {
  try {
    const payload = await c.req.json();
    const eventData = payload.data || payload;
    const emailId = eventData.email_id || payload.email_id;
    const rawTo = eventData.to?.[0] || payload.to?.[0] || '';
    const toAddress = rawTo.toLowerCase().trim();
    const fromAddress = eventData.from || payload.from || 'unknown';
    const subject = eventData.subject || payload.subject || '';

    if (!toAddress) {
      return c.json({ code: 400, message: 'Missing recipient' }, 400);
    }

    // 从环境变量中获取 RESEND_API_KEY
    const apiKey = c.env.RESEND_API_KEY;
    let content = '';

    // 调取 Resend 接收接口获取邮件全文
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

    // 1. 同步存入 KV（供 /m?e= 接口毫秒级轮询，缓存 600 秒）
    if (c.env.kv && code) {
      await c.env.kv.put(`otp:${toAddress}`, code, { expirationTtl: 600 });
      await c.env.kv.put(`raw:${toAddress}`, content.slice(0, 1000), { expirationTtl: 600 });
    }

    // 2. 存入 D1 数据库维持后台面板收件记录
    if (c.env.db) {
      try {
        const emailUuid = crypto.randomUUID();
        const now = Math.floor(Date.now() / 1000);
        await c.env.db.prepare(
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

    return c.json({ code: 200, status: 'success', extracted_code: code });
  } catch (err) {
    console.error('Webhook execution failed:', err);
    return c.json({ code: 500, error: err.message }, 500);
  }
});
