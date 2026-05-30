/**
 * Quo Inbound Webhook Handler — Cloudflare Worker
 * Receives call/SMS events from Quo (formerly OpenPhone), verifies HMAC-SHA256
 * signature, and creates a Paperclip task assigned to Riley Chase (CCO).
 *
 * Required secrets (set via wrangler secret put):
 *   QUO_SIGNING_SECRET   — base64-encoded signing key from Quo webhook settings
 *   PAPERCLIP_API_KEY    — persistent Paperclip agent API key for task creation
 *
 * Required vars (in wrangler.toml):
 *   PAPERCLIP_API_URL    — https://paperclip-api.almawebcreative.com
 */

const RILEY_AGENT_ID = 'f82b2f40-f33b-4595-981d-36ca3149dbe8';
const COMPANY_ID = 'aa9191d4-249a-4574-88f2-1284571ad537';
const GOAL_ID = 'f45eaf59-e75b-4a0a-b6db-b1c7633abb14';

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const body = await request.text();

    // Signature verification
    const signatureHeader = request.headers.get('openphone-signature');
    if (!signatureHeader) {
      return new Response('Missing signature', { status: 401 });
    }

    const isValid = await verifyQuoSignature(signatureHeader, body, env.QUO_SIGNING_SECRET);
    if (!isValid) {
      return new Response('Invalid signature', { status: 401 });
    }

    let event;
    try {
      event = JSON.parse(body);
    } catch {
      return new Response('Invalid JSON', { status: 400 });
    }

    // Process event asynchronously so we return 200 immediately (within 5s requirement)
    const ctx = { waitUntil: (p) => p }; // fallback for non-module workers
    try {
      await handleQuoEvent(event, env);
    } catch (err) {
      console.error('Failed to handle Quo event:', err.message, JSON.stringify(event));
    }

    return new Response('OK', { status: 200 });
  },
};

/**
 * Verify Quo webhook signature.
 * Header format: "hmac;1;{timestamp};{base64-signature}"
 * Signed data: "{timestamp}.{payload}" with whitespace stripped from payload.
 */
async function verifyQuoSignature(header, rawBody, signingSecret) {
  const parts = header.split(';');
  if (parts.length < 4 || parts[0] !== 'hmac') return false;

  const timestamp = parts[2];
  const receivedSig = parts[3];

  // Strip whitespace from body per Quo spec
  const normalizedBody = rawBody.replace(/\s+/g, '');
  const signedData = `${timestamp}.${normalizedBody}`;

  // Decode base64 signing key
  const keyBytes = Uint8Array.from(atob(signingSecret), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const encoder = new TextEncoder();
  const sigBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(signedData));
  const computedSig = btoa(String.fromCharCode(...new Uint8Array(sigBytes)));

  return computedSig === receivedSig;
}

async function handleQuoEvent(event, env) {
  const { type, data = {}, createdAt, id: eventId } = event;

  let taskTitle, taskBody, summary;

  if (type && type.startsWith('call.')) {
    const info = extractCallInfo(data);
    taskTitle = `[Quo] Inbound Call from ${info.fromNumber} — ${formatEventType(type)}`;
    taskBody = buildCallBody(info, event);
    summary = `Call ${info.status} from \`${info.fromNumber}\` | Call ID: \`${info.callId || 'N/A'}\` | Event: \`${eventId}\``;
  } else if (type && type.startsWith('message.')) {
    const info = extractMessageInfo(data);
    taskTitle = `[Quo] Inbound SMS from ${info.fromNumber}`;
    taskBody = buildMessageBody(info, event);
    summary = `SMS from \`${info.fromNumber}\` | "${truncate(info.text, 80)}" | Event: \`${eventId}\``;
  } else {
    console.log(`Ignoring unknown Quo event type: ${type}`);
    return;
  }

  const issueId = await createPaperclipTask(taskTitle, taskBody, env);
  if (issueId) {
    await postComment(issueId, summary, env);
  }
}

function extractCallInfo(data) {
  const participants = data.participants || [];
  // Find the external (inbound) participant
  const external =
    participants.find((p) => p.direction === 'incoming') ||
    participants.find((p) => !p.userId) ||
    participants[0] ||
    {};

  return {
    fromNumber: external.phoneNumber || data.from || 'Unknown',
    toNumber: data.to || 'Unknown',
    direction: data.direction || 'inbound',
    status: data.status || 'unknown',
    duration: data.duration,
    callId: data.id,
    answeredAt: data.answeredAt,
    completedAt: data.completedAt,
    createdAt: data.createdAt,
  };
}

function extractMessageInfo(data) {
  return {
    fromNumber: data.from || 'Unknown',
    toNumber: data.to || 'Unknown',
    direction: data.direction || 'inbound',
    text: data.text || '(no text)',
    status: data.status || 'received',
    messageId: data.id,
    createdAt: data.createdAt,
  };
}

function buildCallBody(info, event) {
  return `## Inbound Call — Quo

| Field | Value |
|---|---|
| **From** | ${info.fromNumber} |
| **To** | ${info.toNumber} |
| **Status** | ${info.status} |
| **Direction** | ${info.direction} |
${info.duration != null ? `| **Duration** | ${info.duration}s |\n` : ''}${info.answeredAt ? `| **Answered** | ${info.answeredAt} |\n` : ''}${info.completedAt ? `| **Completed** | ${info.completedAt} |\n` : ''}| **Call ID** | ${info.callId || 'N/A'} |
| **Event Time** | ${info.createdAt || event.createdAt} |

---

### Raw Quo Payload

\`\`\`json
${JSON.stringify(event, null, 2)}
\`\`\`
`;
}

function buildMessageBody(info, event) {
  return `## Inbound SMS — Quo

| Field | Value |
|---|---|
| **From** | ${info.fromNumber} |
| **To** | ${info.toNumber} |
| **Message** | ${info.text} |
| **Status** | ${info.status} |
| **Message ID** | ${info.messageId || 'N/A'} |
| **Event Time** | ${info.createdAt || event.createdAt} |

---

### Raw Quo Payload

\`\`\`json
${JSON.stringify(event, null, 2)}
\`\`\`
`;
}

async function createPaperclipTask(title, description, env) {
  const res = await fetch(`${env.PAPERCLIP_API_URL}/api/companies/${COMPANY_ID}/issues`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.PAPERCLIP_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      title,
      description,
      assigneeAgentId: RILEY_AGENT_ID,
      goalId: GOAL_ID,
      status: 'todo',
      priority: 'high',
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Paperclip task creation failed ${res.status}: ${text}`);
  }

  const task = await res.json();
  return task.id;
}

async function postComment(issueId, body, env) {
  const res = await fetch(`${env.PAPERCLIP_API_URL}/api/issues/${issueId}/comments`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.PAPERCLIP_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ body }),
  });

  if (!res.ok) {
    console.error(`Comment post failed ${res.status}: ${await res.text()}`);
  }
}

function formatEventType(type) {
  return type.replace('call.', '').replace(/\./g, ' ');
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max) + '…' : str;
}
