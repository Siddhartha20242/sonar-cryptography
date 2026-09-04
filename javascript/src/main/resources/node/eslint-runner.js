const fs = require('fs');
const path = require('path');

let input = '';
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(input);
    const results = [];

    for (const file of request.files) {
      try {
        const content = file.content;
        const calls = [];
        const bindings = {};
        const variableValues = {};
        const resultTypes = {
          createHash: 'crypto.Hash',
          createHmac: 'crypto.Hmac',
          createCipher: 'crypto.Cipher',
          createCipheriv: 'crypto.Cipher',
          createDecipher: 'crypto.Decipher',
          createDecipheriv: 'crypto.Decipher',
          createSign: 'crypto.Sign',
          createVerify: 'crypto.Verify',
          createDiffieHellman: 'crypto.DiffieHellman',
          createECDH: 'crypto.ECDH'
        };

        // Detect crypto module imports
        if (content.includes('require("crypto")') || content.includes("require('crypto')")) {
          bindings.crypto = 'crypto';
        }
        if (content.includes('require("node:crypto")') || content.includes("require('node:crypto')")) {
          bindings['node:crypto'] = 'crypto';
        }
        if (content.includes('require("tls")') || content.includes("require('tls')")) {
          bindings.tls = 'tls';
        }
        if (content.includes('require("node:tls")') || content.includes("require('node:tls')")) {
          bindings['node:tls'] = 'tls';
        }

        // All crypto methods to detect
        const cryptoMethods = [
          'createHash', 'createHmac', 'createCipheriv', 'createDecipheriv',
          'createSign', 'createVerify', 'createDiffieHellman', 'createECDH',
          'createSecretKey', 'createPublicKey', 'createPrivateKey',
          'generateKey', 'generateKeySync', 'generateKeyPair', 'generateKeyPairSync',
          'pbkdf2', 'pbkdf2Sync', 'scrypt', 'scryptSync', 'hkdf', 'hkdfSync',
          'randomBytes', 'randomFill', 'randomFillSync', 'randomInt', 'randomUUID',
          'publicEncrypt', 'privateDecrypt', 'privateEncrypt', 'publicDecrypt',
          'sign', 'verify',
          'update', 'digest', 'final', 'computeSecret', 'generateKeys',
          'createSecureContext', 'connect', 'createServer'
        ];

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          
          // Check for variable assignment patterns: const x = crypto.method(
          const assignRegex = /(?:const|let|var)\s+(\w+)\s*=\s*(crypto|tls)\.(\w+)\s*\(/g;
          let assignMatch;
          while ((assignMatch = assignRegex.exec(line)) !== null) {
            const varName = assignMatch[1];
            const objectName = assignMatch[2];
            const methodName = assignMatch[3];
            
            if (cryptoMethods.includes(methodName)) {
              const args = extractArgs(line, assignMatch.index + assignMatch[0].length - 1);
              const resultType = resultTypes[methodName] || 'object';
              bindings[varName] = resultType;
              calls.push({
                kind: 'call',
                methodName: methodName,
                objectType: objectName,
                resultType: resultType,
                variableName: varName,
                line: i + 1,
                column: assignMatch.index + 1,
                arguments: args
              });
            }
          }
          
          // Check for direct calls: crypto.method(
          const directRegex = /(\w+)\.(\w+)\s*\(/g;
          let directMatch;
          while ((directMatch = directRegex.exec(line)) !== null) {
            const objectName = directMatch[1];
            const methodName = directMatch[2];
            
            // Skip if this was already captured as an assignment
            const assignmentPrefix = /(?:const|let|var)\s+\w+\s*=\s*$/.test(
              line.substring(0, directMatch.index)
            );
            if (assignmentPrefix) {
              continue;
            }
            
            if (cryptoMethods.includes(methodName)) {
              const args = extractArgs(line, directMatch.index + directMatch[0].length - 1);
              calls.push({
                kind: 'call',
                methodName: methodName,
                objectType: bindings[objectName] || objectName,
                resultType: 'object',
                variableName: null,
                line: i + 1,
                column: directMatch.index + 1,
                arguments: args
              });
            }
          }
        }

        results.push({
          path: file.path,
          bindings: bindings,
          variableValues: variableValues,
          calls: calls
        });
      } catch (err) {
        results.push({
          path: file.path,
          parseError: err.message
        });
      }
    }

    console.log(JSON.stringify({ files: results }));
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
});

function extractArgs(line, startIndex) {
  const args = [];
  let parenCount = 0;
  let braceCount = 0;
  let bracketCount = 0;
  let currentArg = '';
  let inString = false;
  let stringChar = '';
  let i = startIndex;
  
  while (i < line.length && line[i] !== '(') i++;
  if (i >= line.length) return args;
  i++;
  
  for (; i < line.length; i++) {
    const ch = line[i];
    
    if ((ch === '"' || ch === "'") && !inString) {
      inString = true;
      stringChar = ch;
      currentArg += ch;
      continue;
    }
    if (inString && ch === stringChar && line[i-1] !== '\\') {
      inString = false;
      stringChar = '';
      currentArg += ch;
      continue;
    }
    if (inString) {
      currentArg += ch;
      continue;
    }
    
    if (ch === '(') parenCount++;
    if (ch === ')') {
      if (parenCount === 0) {
        addArgument(args, currentArg);
        break;
      }
      parenCount--;
    }
    if (ch === '{') braceCount++;
    if (ch === '}') braceCount--;
    if (ch === '[') bracketCount++;
    if (ch === ']') bracketCount--;
    if (ch === ',' && parenCount === 0 && braceCount === 0 && bracketCount === 0) {
      addArgument(args, currentArg);
      currentArg = '';
      continue;
    }
    currentArg += ch;
  }
  
  return args;
}

function addArgument(args, source) {
  const value = source.trim();
  if (!value) return;

  let type = 'any';
  let kind = 'literal';
  let normalizedValue = value;
  if (/^(['"]).*\1$/s.test(value)) {
    type = 'string';
    normalizedValue = value.slice(1, -1);
  } else if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(value)) {
    type = 'number';
  } else if (value === 'true' || value === 'false') {
    type = 'boolean';
  } else if (value.startsWith('{') && value.endsWith('}')) {
    type = 'object';
  } else if (value.startsWith('[') && value.endsWith(']')) {
    type = 'array';
  } else if (/^[A-Za-z_$][\w$]*$/.test(value)) {
    kind = 'identifier';
  }

  args.push({ kind, type, value: normalizedValue, line: 0, column: 0 });
}
