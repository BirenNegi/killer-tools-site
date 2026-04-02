<script setup lang="ts">
import { Check, Copy } from '@vicons/tabler';

const rawHeaders = ref('');
const parsed = ref(false);
const copiedValue = ref<string | null>(null);

function copyValue(value: string) {
  navigator.clipboard.writeText(value);
  copiedValue.value = value;
  setTimeout(() => {
    copiedValue.value = null;
  }, 1500);
}

interface Hop {
  from: string
  by: string
  ip: string
  timestamp: string
  delay: string
}

interface AuthResult {
  protocol: string
  result: string
  detail: string
}

interface ParsedHeaders {
  fields: { label: string; value: string }[]
  hops: Hop[]
  auth: AuthResult[]
  spamScore: string | null
  spamStatus: string | null
}

const result = ref<ParsedHeaders | null>(null);

function getHeader(lines: string[], name: string): string {
  const lower = name.toLowerCase();
  const found = lines.find((l: string) => l.toLowerCase().startsWith(`${lower}:`));
  return found ? found.slice(name.length + 1).trim() : '';
}

function getAllHeaders(lines: string[], name: string): string[] {
  const lower = name.toLowerCase();
  return lines
    .filter((l: string) => l.toLowerCase().startsWith(`${lower}:`))
    .map((l: string) => l.slice(name.length + 1).trim());
}

function extractIp(text: string): string {
  const match = text.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  if (match) {
    return match[1];
  }
  const bare = text.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return bare ? bare[1] : '';
}

function parseReceivedHops(receivedHeaders: string[]): Hop[] {
  const hops: Hop[] = [];
  const dates: (Date | null)[] = [];

  for (const raw of receivedHeaders) {
    const dateMatch = raw.match(/;\s*(.+)$/);
    const dateStr = dateMatch ? dateMatch[1].trim() : '';
    const date = dateStr ? new Date(dateStr) : null;
    dates.push(date);

    const fromMatch = raw.match(/from\s+([^\s(]+)/i);
    const byMatch = raw.match(/by\s+([^\s(]+)/i);

    hops.push({
      from: fromMatch ? fromMatch[1] : '',
      by: byMatch ? byMatch[1] : '',
      ip: extractIp(raw),
      timestamp: dateStr,
      delay: '',
    });
  }

  for (let i = 0; i < hops.length - 1; i++) {
    const curr = dates[i];
    const next = dates[i + 1];
    if (curr && next) {
      const diff = Math.round((curr.getTime() - next.getTime()) / 1000);
      hops[i].delay = diff >= 0 ? `+${diff}s` : `${diff}s`;
    }
  }

  return hops;
}

function parseAuthResults(lines: string[]): AuthResult[] {
  const authHeaders = getAllHeaders(lines, 'Authentication-Results');
  const results: AuthResult[] = [];

  for (const header of authHeaders) {
    const protocols = ['spf', 'dkim', 'dmarc', 'arc'];
    for (const proto of protocols) {
      const rx = new RegExp(`${proto}=([a-z]+)([^;]*)`, 'gi');
      let match;
      // eslint-disable-next-line no-cond-assign
      while ((match = rx.exec(header)) !== null) {
        results.push({
          protocol: proto.toUpperCase(),
          result: match[1].toLowerCase(),
          detail: match[2].trim().replace(/\s+/g, ' '),
        });
      }
    }
  }

  return results;
}

function parseHeaders() {
  const raw = rawHeaders.value.trim();
  if (!raw) {
    return;
  }

  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/).filter((l: string) => l.includes(':'));

  const fields: { label: string; value: string }[] = [
    { label: 'From', value: getHeader(lines, 'From') },
    { label: 'To', value: getHeader(lines, 'To') },
    { label: 'Subject', value: getHeader(lines, 'Subject') },
    { label: 'Date', value: getHeader(lines, 'Date') },
    { label: 'Message-ID', value: getHeader(lines, 'Message-ID') },
    { label: 'Reply-To', value: getHeader(lines, 'Reply-To') },
    { label: 'Return-Path', value: getHeader(lines, 'Return-Path') },
    { label: 'X-Originating-IP', value: getHeader(lines, 'X-Originating-IP') || getHeader(lines, 'X-Sender-IP') },
    { label: 'X-Mailer', value: getHeader(lines, 'X-Mailer') },
    { label: 'MIME-Version', value: getHeader(lines, 'MIME-Version') },
  ].filter(f => f.value);

  const receivedRaw = getAllHeaders(lines, 'Received');
  const hops = parseReceivedHops(receivedRaw);
  const auth = parseAuthResults(lines);

  const spamScore = getHeader(lines, 'X-Spam-Score') || getHeader(lines, 'X-Spam-Level') || null;
  const spamStatus = getHeader(lines, 'X-Spam-Status') || null;

  result.value = { fields, hops, auth, spamScore, spamStatus };
  parsed.value = true;
}

function reset() {
  rawHeaders.value = '';
  result.value = null;
  parsed.value = false;
}

function authStatusType(r: string): 'success' | 'error' | 'warning' | 'default' {
  if (r === 'pass') {
    return 'success';
  }
  if (r === 'fail' || r === 'reject') {
    return 'error';
  }
  if (r === 'softfail' || r === 'neutral' || r === 'temperror' || r === 'permerror') {
    return 'warning';
  }
  return 'default';
}

const protocolOrder = ['DMARC', 'SPF', 'DKIM', 'ARC'];

const groupedAuth = computed(() => {
  if (!result.value?.auth) {
    return [];
  }
  const groups: Record<string, typeof result.value.auth> = {};
  for (const a of result.value.auth) {
    if (!groups[a.protocol]) {
      groups[a.protocol] = [];
    }
    groups[a.protocol].push(a);
  }
  return protocolOrder
    .filter(p => groups[p])
    .map(p => ({ protocol: p, entries: groups[p] }))
    .concat(
      Object.keys(groups)
        .filter(p => !protocolOrder.includes(p))
        .map(p => ({ protocol: p, entries: groups[p] })),
    );
});
</script>

<template>
  <div style="flex: 1 1 900px; max-width: 1400px; margin-top: -28px;">
    <template v-if="!parsed">
      <div class="text-xs op-60 mb-2">
        Paste raw email headers below — in most email clients: View Source, Show Original, or View Message Headers
      </div>
      <c-input-text
        v-model:value="rawHeaders"
        placeholder="Received: from mail.example.com...&#10;From: sender@example.com&#10;To: recipient@example.com&#10;Subject: ..."
        :rows="12"
        multiline
        mb-4
      />
      <div flex justify-end gap-3>
        <c-button :disabled="!rawHeaders.trim()" @click="parseHeaders">
          Parse Headers
        </c-button>
      </div>
    </template>

    <template v-if="parsed && result">
      <div flex justify-end mb-4>
        <c-button variant="text" @click="reset">
          ← Parse Another
        </c-button>
      </div>

      <div class="grid grid-cols-1 gap-16px lg:grid-cols-2">

        <!-- Left: Message Details + Delivery Hops -->
        <div class="grid grid-cols-1 gap-16px" style="align-content: start;">
          <c-card>
            <div flex items-center justify-between mb-3>
              <span class="text-lg font-bold">Message Details</span>
            </div>
            <div class="grid grid-cols-1 gap-8px">
              <div
                v-for="field in result.fields"
                :key="field.label"
                flex items-start justify-between gap-2
                class="p-2 rounded"
                style="background: rgba(255,255,255,0.05)"
              >
                <div style="min-width: 0;">
                  <div class="text-xs op-50 mb-0.5">
                    {{ field.label }}
                  </div>
                  <div class="text-xs font-mono" style="overflow-wrap: break-word; word-break: normal;">
                    {{ field.value }}
                  </div>
                </div>
                <c-button circle variant="text" style="width:20px;height:20px;flex-shrink:0;" @click="copyValue(field.value)">
                  <n-icon size="12" :component="copiedValue === field.value ? Check : Copy" />
                </c-button>
              </div>
            </div>
          </c-card>

          <c-card v-if="result.hops.length">
            <div flex items-center justify-between mb-3>
              <span class="text-lg font-bold">Delivery Hops</span>
              <span class="text-xs op-50">oldest first</span>
            </div>
            <div
              v-for="(hop, i) in [...result.hops].reverse()"
              :key="i"
              mb-3
            >
              <div flex items-center gap-2 mb-1>
                <n-tag size="small" type="default">
                  Hop {{ i + 1 }}
                </n-tag>
                <span v-if="hop.delay" class="text-xs op-40">{{ hop.delay }}</span>
              </div>
              <div
                class="p-2 rounded text-xs font-mono"
                style="background: rgba(255,255,255,0.05); overflow-wrap: break-word; word-break: normal;"
              >
                <div v-if="hop.from" class="mb-1">
                  <span class="op-50">From: </span>{{ hop.from }}
                  <span v-if="hop.ip" class="op-50"> [{{ hop.ip }}]</span>
                </div>
                <div v-if="hop.by" class="mb-1">
                  <span class="op-50">By: </span>{{ hop.by }}
                </div>
                <div v-if="hop.timestamp" class="op-40">
                  {{ hop.timestamp }}
                </div>
              </div>
            </div>
          </c-card>
        </div>

        <!-- Right: Auth Results + Spam -->
        <div class="grid grid-cols-1 gap-16px" style="align-content: start;">
          <c-card v-if="result.auth.length">
            <div flex items-center justify-between mb-3>
              <span class="text-lg font-bold">Authentication Results</span>
            </div>
            <div class="grid grid-cols-1 gap-12px">
              <div
                v-for="group in groupedAuth"
                :key="group.protocol"
              >
                <div class="text-xs font-bold font-mono op-60 mb-1 uppercase tracking-wider">
                  {{ group.protocol }}
                </div>
                <div class="grid grid-cols-1 gap-8px sm:grid-cols-2">
                  <div
                    v-for="(a, i) in group.entries"
                    :key="i"
                    class="p-2 rounded"
                    style="background: rgba(255,255,255,0.05)"
                  >
                    <div flex items-center gap-2 mb-1>
                      <n-tag :type="authStatusType(a.result)" size="small">
                        {{ a.result }}
                      </n-tag>
                    </div>
                    <div v-if="a.detail" class="text-xs font-mono op-50" style="overflow-wrap: break-word; word-break: normal;">
                      {{ a.detail }}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </c-card>

          <c-card v-if="result.spamScore || result.spamStatus">
            <div flex items-center justify-between mb-3>
              <span class="text-lg font-bold">Spam Analysis</span>
            </div>
            <div class="grid grid-cols-1 gap-8px">
              <div
                v-if="result.spamScore"
                class="p-2 rounded"
                style="background: rgba(255,255,255,0.05)"
              >
                <div class="text-xs op-50 mb-0.5">
                  Spam Score
                </div>
                <div class="text-xs font-mono">
                  {{ result.spamScore }}
                </div>
              </div>
              <div
                v-if="result.spamStatus"
                class="p-2 rounded"
                style="background: rgba(255,255,255,0.05)"
              >
                <div class="text-xs op-50 mb-0.5">
                  Spam Status
                </div>
                <div class="text-xs font-mono" style="overflow-wrap: break-word; word-break: normal;">
                  {{ result.spamStatus }}
                </div>
              </div>
            </div>
          </c-card>
        </div>

      </div>
    </template>
  </div>
</template>
