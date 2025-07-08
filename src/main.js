import { Client, Users } from 'node-appwrite';
import * as bip39 from 'bip39'
import * as bitcoin from 'bitcoinjs-lib'
import { ethers } from 'ethers'
import crypto from 'crypto'

// This Appwrite function will be executed every time your function is triggered
export default async ({ req, res, log, error }) => {
  // You can use the Appwrite SDK to interact with other services
  // For this example, we're using the Users service
  const client = new Client()
    .setEndpoint(process.env.APPWRITE_FUNCTION_API_ENDPOINT)
    .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
    .setKey(req.headers['x-appwrite-key'] ?? '');
  const users = new Users(client);

  try {
    const response = await users.list();
    // Log messages and errors to the Appwrite Console
    // These logs won't be seen by your end users
    log(`Total users: ${response.total}`);
  } catch(err) {
    error("Could not list users: " + err.message);
  }

  // The req object contains the request data
  if (req.path === "/ping") {
    // Use res object to respond with text(), json(), or binary()
    // Don't forget to return a response!
    return res.text("Pong");
  }

  try {
    // Parse input
    const {
      walletType,
      blockchain,
      mnemonic,
      walletPassword,
      walletName,
      derivationPath
    } = req.body ? JSON.parse(req.body) : {}

    if (!walletType || !blockchain || !walletPassword || !walletName) {
      return res.json({ error: 'Missing required fields' }, 400)
    }

    // Helper: AES-256-GCM encryption
    function encrypt(data, password) {
      const salt = crypto.randomBytes(16)
      const iv = crypto.randomBytes(12)
      const key = crypto.scryptSync(password, salt, 32)
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
      const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()])
      const tag = cipher.getAuthTag()
      return [
        salt.toString('base64'),
        iv.toString('base64'),
        tag.toString('base64'),
        encrypted.toString('base64')
      ].join('.')
    }

    let result

    if (blockchain === 'bitcoin') {
      // Bitcoin wallet
      let usedMnemonic = mnemonic
      if (!mnemonic) {
        usedMnemonic = bip39.generateMnemonic()
      }
      const seed = await bip39.mnemonicToSeed(usedMnemonic)
      const path = derivationPath || "m/84'/0'/0'/0/0"
      const root = bitcoin.bip32.fromSeed(seed)
      const child = root.derivePath(path)
      const { address } = bitcoin.payments.p2wpkh({ pubkey: child.publicKey })
      result = {
        walletAddress: address,
        publicKey: child.publicKey.toString('hex'),
        encryptedPrivateKey: encrypt(child.toWIF(), walletPassword),
        derivationPath: path,
        mnemonic: walletType === 'imported' ? usedMnemonic : undefined
      }
    } else {
      // Ethereum-like wallet
      let usedMnemonic = mnemonic
      let path = derivationPath || "m/44'/60'/0'/0/0"
      if (!mnemonic) {
        usedMnemonic = ethers.Wallet.createRandom().mnemonic.phrase
      }
      const wallet = ethers.Wallet.fromMnemonic(usedMnemonic, path)
      result = {
        walletAddress: wallet.address,
        publicKey: wallet.publicKey,
        encryptedPrivateKey: encrypt(wallet.privateKey, walletPassword),
        derivationPath: path,
        mnemonic: walletType === 'imported' ? usedMnemonic : undefined
      }
    }

    // Never store mnemonic, only return if imported and user requests
    return res.json({
      walletAddress: result.walletAddress,
      publicKey: result.publicKey,
      encryptedPrivateKey: result.encryptedPrivateKey,
      derivationPath: result.derivationPath,
      mnemonic: result.mnemonic // Only for imported
    })
  } catch (err) {
    error('Wallet creation failed: ' + (err.message || err))
    return res.json({ error: err.message || 'Wallet creation failed' }, 500)
  }

};
