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
      walletType,        // 'inbuilt', 'imported', 'external'
      blockchain,        // 'bitcoin', 'ethereum', etc.
      mnemonic,          // optional, for import
      walletPassword,    // required for inbuilt/imported
      walletName,        // required
      derivationPath,    // optional
      walletAddress,     // required for external
      publicKey          // optional for external
    } = req.bodyJson || {}

    // Validate walletType
    if (!walletType || !['inbuilt', 'imported', 'external'].includes(walletType)) {
      return res.json({ error: 'Invalid or missing walletType' }, 400)
    }
    if (!blockchain || !walletName) {
      return res.json({ error: 'Missing required fields' }, 400)
    }

    // Handle external wallet (address only, no private key)
    if (walletType === 'external') {
      if (!walletAddress) {
        return res.json({ error: 'walletAddress required for external wallet' }, 400)
      }
      return res.json({
        walletAddress,
        publicKey: publicKey || null,
        encryptedPrivateKey: null,
        derivationPath: null,
        mnemonic: null,
        creationMethod: 'external'
      })
    }

    // For inbuilt/imported, walletPassword is required
    if (!walletPassword) {
      return res.json({ error: 'walletPassword required' }, 400)
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
      if (walletType === 'inbuilt' && !mnemonic) {
        usedMnemonic = bip39.generateMnemonic()
      }
      if (!usedMnemonic) {
        return res.json({ error: 'mnemonic required for imported wallet' }, 400)
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
        mnemonic: walletType === 'imported' ? usedMnemonic : undefined,
        creationMethod: walletType
      }
    } else if (blockchain === 'ethereum') {
      // Ethereum wallet
      let usedMnemonic = mnemonic
      let path = derivationPath || "m/44'/60'/0'/0/0"
      if (walletType === 'inbuilt' && !mnemonic) {
        usedMnemonic = ethers.Wallet.createRandom().mnemonic.phrase
      }
      if (!usedMnemonic) {
        return res.json({ error: 'mnemonic required for imported wallet' }, 400)
      }
      const wallet = ethers.Wallet.fromMnemonic(usedMnemonic, path)
      result = {
        walletAddress: wallet.address,
        publicKey: wallet.publicKey,
        encryptedPrivateKey: encrypt(wallet.privateKey, walletPassword),
        derivationPath: path,
        mnemonic: walletType === 'imported' ? usedMnemonic : undefined,
        creationMethod: walletType
      }
    } else {
      return res.json({ error: 'Unsupported blockchain' }, 400)
    }

    // Never store mnemonic, only return if imported and user requests
    return res.json({
      walletAddress: result.walletAddress,
      publicKey: result.publicKey,
      encryptedPrivateKey: result.encryptedPrivateKey,
      derivationPath: result.derivationPath,
      mnemonic: result.mnemonic,
      creationMethod: result.creationMethod
    })
  } catch (err) {
    error('Wallet creation failed: ' + (err.message || err))
    return res.json({ error: err.message || 'Wallet creation failed' }, 500)
  }

};
