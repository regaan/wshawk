'use strict';

const readline = require('readline');

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', (line) => {
    const request = JSON.parse(line);
    const response = {
        version: '1',
        id: request.id,
        result: request.method === 'system.shutdown'
            ? { accepted: true }
            : { status: 'ready' },
    };
    process.stdout.write(`${JSON.stringify(response)}\n`, () => {
        if (request.method === 'system.shutdown') process.exit(0);
    });
});
