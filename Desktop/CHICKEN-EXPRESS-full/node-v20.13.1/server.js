const express = require('express');
const axios = require('axios');
const app = express();
const PORT = 3000; 

app.use(express.json());

app.post('/print', async (req, res) => {
    const receipt = req.body.receipt;

    if (!receipt) {
        return res.status(400).json({ error: 'No receipt content provided' });
    }

    try {
        const response = await axios.post('http://192.168.88.85:8000/print', {
            receipt: receipt
        });

        if (response.status === 200) {
            return res.status(200).json({ message: 'Receipt sent to printer' });
        } else {
            return res.status(500).json({ error: 'Failed to send receipt to printer' });
        }
    } catch (error) {
        console.error('Error sending data to printer:', error);
        return res.status(500).json({ error: 'Failed to send receipt to printer' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
