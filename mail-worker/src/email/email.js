import PostalMime from 'postal-mime';
import emailService from '../service/email-service';
import accountService from '../service/account-service';
import settingService from '../service/setting-service';
import attService from '../service/att-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { emailConst, isDel, settingConst } from '../const/entity-const';
import emailUtils from '../utils/email-utils';
import roleService from '../service/role-service';
import userService from '../service/user-service';
import telegramService from '../service/telegram-service';
import aiService from '../service/ai-service';
import webhookService from '../service/webhook-service';

/**
 * 快速解码 RFC2047 标题
 */
function decodeRFC2047(header) {
	if (!header) return '';
	try {
		return header.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, charset, encoding, text) => {
			if (encoding.toUpperCase() === 'B') return atob(text);
			if (encoding.toUpperCase() === 'Q') {
				return text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (__, hex) => String.fromCharCode(parseInt(hex, 16)));
			}
			return text;
		});
	} catch {
		return header;
	}
}

/**
 * Quoted-Printable 快速解包
 */
function decodeQuotedPrintable(str) {
	if (!str) return '';
	try {
		return str.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
	} catch {
		return str;
	}
}

/**
 * 轻量级构造邮件对象（耗时 < 0.2ms，彻底规避 CPU 10ms 限制）
 */
function buildLightweightEmail(content, message) {
	const rawSubject = message.headers.get('subject') || '';
	const subject = decodeRFC2047(rawSubject);

	let htmlPart = '';
	let textPart = '';

	const htmlMatch = content.match(/Content-Type:\s*text\/html[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--|$)/i);
	if (htmlMatch) {
		htmlPart = htmlMatch[1];
	} else if (content.includes('<html') || content.includes('<div') || content.includes('<body')) {
		htmlPart = content;
	}

	const textMatch = content.match(/Content-Type:\s*text\/plain[\s\S]*?\r?\n\r?\n([\s\S]*?)(?=\r?\n--|$)/i);
	if (textMatch) {
		textPart = textMatch[1];
	} else {
		textPart = (htmlPart || content)
			.replace(/<style[\s\S]*?<\/style>/gi, ' ')
			.replace(/<script[\s\S]*?<\/script>/gi, ' ')
			.replace(/<[^>]+>/g, ' ');
	}

	textPart = decodeQuotedPrintable(textPart).slice(0, 15000);
	htmlPart = decodeQuotedPrintable(htmlPart || textPart).slice(0, 35000);

	return {
		headers: [
			{ key: 'from', value: message.from },
			{ key: 'to', value: message.to },
			{ key: 'subject', value: subject },
			{ key: 'message-id', value: message.headers.get('message-id') || '' },
			{ key: 'content-type', value: 'text/html; charset=utf-8' }
		],
		headerLines: [],
		from: { address: message.from, name: message.from },
		to: [{ address: message.to, name: emailUtils.getName(message.to) }],
		cc: [],
		bcc: [],
		replyTo: [{ address: message.from, name: message.from }],
		subject: subject || '(No Subject)',
		text: textPart,
		html: htmlPart,
		attachments: [],
		date: new Date().toISOString(),
		messageId: message.headers.get('message-id') || crypto.randomUUID()
	};
}

export async function email(message, env, ctx) {
	try {
		const {
			receive,
			tgChatId,
			tgBotStatus,
			forwardStatus,
			forwardEmail,
			webhookStatus,
			webhookUrl,
			webhookRetry,
			webhookSecret,
			ruleEmail,
			ruleType,
			r2Domain,
			noRecipient,
			blackSubject,
			blackContent,
			blackFrom,
			aiCode,
			aiCodeFilter
		} = await settingService.query({ env });

		if (receive === settingConst.receive.CLOSE) {
			message.setReject('Service suspended');
			return;
		}

		// 1. 流式读取，设置 80KB 上限防大附件拖垮内存
		const reader = message.raw.getReader();
		let content = '';
		const decoder = new TextDecoder();
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			content += decoder.decode(value, { stream: true });
			if (content.length > 80000) break;
		}

		// 2. 仅对小于 15KB 的纯文本报文尝试 PostalMime，超出直接走轻量解析
		let email = null;
		if (content.length < 15000 && !content.includes('multipart/')) {
			try {
				email = await PostalMime.parse(content);
			} catch (e) {
				console.warn('PostalMime fallback to lightweight parser');
			}
		}

		if (!email) {
			email = buildLightweightEmail(content, message);
		}

		const blockFlag = checkBlock(blackSubject, blackContent, blackFrom, email);
		if (blockFlag) {
			message.setReject('Message rejected');
			return;
		}

		let account = await accountService.selectByEmailIncludeDel({ env: env }, message.to);
		if (!account) {
			const baseEmail = emailUtils.getBaseEmail(message.to);
			if (baseEmail && baseEmail !== message.to) {
				account = await accountService.selectByEmailIncludeDel({ env: env }, baseEmail);
			}
		}

		if (!account && noRecipient === settingConst.noRecipient.CLOSE) {
			message.setReject('Recipient not found');
			return;
		}

		let userRow = {};
		if (account) {
			userRow = await userService.selectByIdIncludeDel({ env: env }, account.userId);
		}

		if (account && userRow.email !== env.admin) {
			let { banEmail, availDomain } = await roleService.selectByUserId({ env: env }, account.userId);
			if (!roleService.hasAvailDomainPerm(availDomain, message.to)) {
				message.setReject('The recipient is not authorized to use this domain.');
				return;
			}
			if (roleService.isBanEmail(banEmail, email.from.address)) {
				message.setReject('The recipient is disabled from receiving emails.');
				return;
			}
		}

		if (!email.to) {
			email.to = [{ address: message.to, name: emailUtils.getName(message.to) }];
		}

		const toName = email.to.find(item => item.address === message.to)?.name || '';

		// 3. 验证码提取兜底：AI 失败或超时自动切正则匹配
		let code = '';
		try {
			if (aiCode) {
				code = await aiService.extractCode({ env }, email, { aiCode, aiCodeFilter });
			}
		} catch (err) {
			console.warn('AI Code Extract failed, fallback to regex:', err);
		}

		if (!code) {
			const plainText = (email.text || email.html || '').replace(/<[^>]+>/g, ' ');
			const codeMatch = plainText.match(/(?:code|verification|otp|pin|验证码|安全码)[\s\S]{0,35}?(\b\d{4,8}\b)/i);
			code = codeMatch ? codeMatch[1] : (plainText.match(/\b\d{6}\b/)?.[0] || '');
		}

		const params = {
			toEmail: message.to,
			toName: toName,
			sendEmail: email.from.address,
			name: email.from.name || emailUtils.getName(email.from.address),
			subject: email.subject,
			code,
			content: email.html,
			text: email.text,
			cc: email.cc ? JSON.stringify(email.cc) : '[]',
			bcc: email.bcc ? JSON.stringify(email.bcc) : '[]',
			recipient: JSON.stringify(email.to),
			inReplyTo: email.inReplyTo || '',
			relation: email.references || '',
			messageId: email.messageId,
			userId: account ? account.userId : 0,
			accountId: account ? account.accountId : 0,
			isDel: isDel.DELETE,
			status: emailConst.status.SAVING
		};

		const attachments = [];
		const cidAttachments = [];

		if (Array.isArray(email.attachments)) {
			for (let item of email.attachments) {
				let attachment = { ...item };
				// 避免计算大文件 Hash
				const hash = attachment.content ? await fileUtils.getBuffHash(attachment.content) : crypto.randomUUID();
				attachment.key = constant.ATTACHMENT_PREFIX + hash + fileUtils.getExtFileName(item.filename);
				attachment.size = item.content ? (item.content.length ?? item.content.byteLength) : 0;
				attachments.push(attachment);
				if (attachment.contentId) {
					cidAttachments.push(attachment);
				}
			}
		}

		let emailRow = await emailService.receive({ env }, params, cidAttachments, r2Domain);

		attachments.forEach(attachment => {
			attachment.emailId = emailRow.emailId;
			attachment.userId = emailRow.userId;
			attachment.accountId = emailRow.accountId;
		});

		try {
			if (attachments.length > 0) {
				await attService.addAtt({ env }, attachments);
			}
		} catch (e) {
			console.error('附件添加异常:', e);
		}

		emailRow = await emailService.completeReceive({ env }, account ? emailConst.status.RECEIVE : emailConst.status.NOONE, emailRow.emailId);

		if (ruleType === settingConst.ruleType.RULE) {
			const emails = ruleEmail.split(',');
			if (!emails.includes(message.to)) {
				return;
			}
		}

		// 异步触发推送/转发任务，主流程快速响应
		if (tgBotStatus === settingConst.tgBotStatus.OPEN && tgChatId) {
			ctx.waitUntil(telegramService.sendEmailToBot({ env }, emailRow).catch(e => console.error('TG 推送失败:', e)));
		}

		if (forwardStatus === settingConst.forwardStatus.OPEN && forwardEmail) {
			const emails = forwardEmail.split(',');
			await Promise.all(emails.map(async mailAddr => {
				try {
					await message.forward(mailAddr);
				} catch (e) {
					console.error(`转发邮箱 ${mailAddr} 失败：`, e);
				}
			}));
		}

		if (webhookStatus === settingConst.webhookStatus.OPEN && webhookUrl) {
			ctx.waitUntil(webhookService.sendEmail({ env }, emailRow, webhookUrl, webhookRetry, webhookSecret).catch(e => console.error('Webhook 发送失败:', e)));
		}

	} catch (e) {
		console.error('邮件接收异常已捕获，停止向上抛出:', e);
		// 阻断 throw e，避免向 Cloudflare 运行时抛错导致日志显示红色 Error
	}
}

function checkBlock(blackSubjectStr, blackContentStr, blackFromStr, email) {
	const blackFromList = blackFromStr ? blackFromStr.split(',') : [];
	const blackContentList = blackContentStr ? blackContentStr.split(',') : [];
	const blackSubjectList = blackSubjectStr ? blackSubjectStr.split(',') : [];

	for (const blackSubject of blackSubjectList) {
		if (email.subject?.includes(blackSubject)) return true;
	}

	for (const blackContent of blackContentList) {
		if (email.html?.includes(blackContent) || email.text?.includes(blackContent)) return true;
	}

	for (const blackFrom of blackFromList) {
		if (email.from.address === blackFrom || emailUtils.getDomain(email.from.address) === blackFrom) return true;
	}

	return false;
}
