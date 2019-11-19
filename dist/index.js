"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var ethUtil = require("ethereumjs-util");
var bs58check = require('bs58check');
var randomBytes = require('randombytes');
var scryptsy = require('scrypt.js');
var uuidv4 = require('uuid/v4');
function validateHexString(paramName, str, length) {
    if (str.toLowerCase().startsWith('0x')) {
        str = str.slice(2);
    }
    if (!str && !length) {
        return str;
    }
    if (length % 2) {
        throw new Error("Invalid length argument, must be an even number");
    }
    if (typeof length === 'number' && str.length !== length) {
        throw new Error("Invalid " + paramName + ", string must be " + length + " hex characters");
    }
    if (!/^([0-9a-f]{2})+$/i.test(str)) {
        var howMany = typeof length === 'number' ? length : 'empty or a non-zero even number of';
        throw new Error("Invalid " + paramName + ", string must be " + howMany + " hex characters");
    }
    return str;
}
function validateBuffer(paramName, buff, length) {
    if (!Buffer.isBuffer(buff)) {
        var howManyHex = typeof length === 'number' ? "" + length * 2 : 'empty or a non-zero even number of';
        var howManyBytes = typeof length === 'number' ? " (" + length + " bytes)" : '';
        throw new Error("Invalid " + paramName + ", must be a string (" + howManyHex + " hex characters) or buffer" + howManyBytes);
    }
    if (typeof length === 'number' && buff.length !== length) {
        throw new Error("Invalid " + paramName + ", buffer must be " + length + " bytes");
    }
    return buff;
}
function mergeToV3ParamsWithDefaults(params) {
    var v3Defaults = {
        cipher: 'aes-128-ctr',
        kdf: 'scrypt',
        salt: randomBytes(32),
        iv: randomBytes(16),
        uuid: randomBytes(16),
        dklen: 32,
        c: 262144,
        n: 262144,
        r: 8,
        p: 1,
    };
    if (!params) {
        return v3Defaults;
    }
    if (typeof params.salt === 'string') {
        params.salt = Buffer.from(validateHexString('salt', params.salt), 'hex');
    }
    if (typeof params.iv === 'string') {
        params.iv = Buffer.from(validateHexString('iv', params.iv, 32), 'hex');
    }
    if (typeof params.uuid === 'string') {
        params.uuid = Buffer.from(validateHexString('uuid', params.uuid, 32), 'hex');
    }
    if (params.salt) {
        validateBuffer('salt', params.salt);
    }
    if (params.iv) {
        validateBuffer('iv', params.iv, 16);
    }
    if (params.uuid) {
        validateBuffer('uuid', params.uuid, 16);
    }
    return __assign(__assign({}, v3Defaults), params);
}
function kdfParamsForPBKDF(opts) {
    return {
        dklen: opts.dklen,
        salt: opts.salt,
        c: opts.c,
        prf: 'hmac-sha256',
    };
}
function kdfParamsForScrypt(opts) {
    return {
        dklen: opts.dklen,
        salt: opts.salt,
        n: opts.n,
        r: opts.r,
        p: opts.p,
    };
}
// wallet implementation
var Wallet = /** @class */ (function () {
    function Wallet(privateKey, publicKey) {
        if (publicKey === void 0) { publicKey = undefined; }
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        if (privateKey && publicKey) {
            throw new Error('Cannot supply both a private and a public key to the constructor');
        }
        if (privateKey && !ethUtil.isValidPrivate(privateKey)) {
            throw new Error('Private key does not satisfy the curve requirements (ie. it is invalid)');
        }
        if (publicKey && !ethUtil.isValidPublic(publicKey)) {
            throw new Error('Invalid public key');
        }
    }
    // static methods
    Wallet.generate = function (icapDirect) {
        if (icapDirect === void 0) { icapDirect = false; }
        if (icapDirect) {
            var max = new ethUtil.BN('088f924eeceeda7fe92e1f5b0fffffffffffffff', 16);
            while (true) {
                var privateKey = randomBytes(32);
                if (new ethUtil.BN(ethUtil.privateToAddress(privateKey)).lte(max)) {
                    return new Wallet(privateKey);
                }
            }
        }
        else {
            return new Wallet(randomBytes(32));
        }
    };
    Wallet.generateVanityAddress = function (pattern) {
        if (!(pattern instanceof RegExp)) {
            pattern = new RegExp(pattern);
        }
        while (true) {
            var privateKey = randomBytes(32);
            var address = ethUtil.privateToAddress(privateKey);
            if (pattern.test(address.toString('hex'))) {
                return new Wallet(privateKey);
            }
        }
    };
    Wallet.fromPublicKey = function (publicKey, nonStrict) {
        if (nonStrict === void 0) { nonStrict = false; }
        if (nonStrict) {
            publicKey = ethUtil.importPublic(publicKey);
        }
        return new Wallet(undefined, publicKey);
    };
    Wallet.fromExtendedPublicKey = function (extendedPublicKey) {
        if (extendedPublicKey.slice(0, 4) !== 'xpub') {
            throw new Error('Not an extended public key');
        }
        var publicKey = bs58check.decode(extendedPublicKey).slice(45);
        // Convert to an Ethereum public key
        return Wallet.fromPublicKey(publicKey, true);
    };
    Wallet.fromPrivateKey = function (privateKey) {
        return new Wallet(privateKey);
    };
    Wallet.fromExtendedPrivateKey = function (extendedPrivateKey) {
        if (extendedPrivateKey.slice(0, 4) !== 'xprv') {
            throw new Error('Not an extended private key');
        }
        var tmp = bs58check.decode(extendedPrivateKey);
        if (tmp[45] !== 0) {
            throw new Error('Invalid extended private key');
        }
        return Wallet.fromPrivateKey(tmp.slice(46));
    };
    Wallet.fromV1 = function (input, password) {
        var json = typeof input === 'object' ? input : JSON.parse(input);
        if (json.Version !== '1') {
            throw new Error('Not a V1 Wallet');
        }
        if (json.Crypto.KeyHeader.Kdf !== 'scrypt') {
            throw new Error('Unsupported key derivation scheme');
        }
        var kdfparams = json.Crypto.KeyHeader.KdfParams;
        var derivedKey = scryptsy(Buffer.from(password), Buffer.from(json.Crypto.Salt, 'hex'), kdfparams.N, kdfparams.R, kdfparams.P, kdfparams.DkLen);
        var ciphertext = Buffer.from(json.Crypto.CipherText, 'hex');
        var mac = ethUtil.keccak256(Buffer.concat([derivedKey.slice(16, 32), ciphertext]));
        if (mac.toString('hex') !== json.Crypto.MAC) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }
        var decipher = crypto.createDecipheriv('aes-128-cbc', ethUtil.keccak256(derivedKey.slice(0, 16)).slice(0, 16), Buffer.from(json.Crypto.IV, 'hex'));
        var seed = runCipherBuffer(decipher, ciphertext);
        return new Wallet(seed);
    };
    Wallet.fromV3 = function (input, password, nonStrict) {
        if (nonStrict === void 0) { nonStrict = false; }
        var json = typeof input === 'object' ? input : JSON.parse(nonStrict ? input.toLowerCase() : input);
        if (json.version !== 3) {
            throw new Error('Not a V3 wallet');
        }
        var derivedKey, kdfparams;
        if (json.crypto.kdf === 'scrypt') {
            kdfparams = json.crypto.kdfparams;
            // FIXME: support progress reporting callback
            derivedKey = scryptsy(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
        }
        else if (json.crypto.kdf === 'pbkdf2') {
            kdfparams = json.crypto.kdfparams;
            if (kdfparams.prf !== 'hmac-sha256') {
                throw new Error('Unsupported parameters to PBKDF2');
            }
            derivedKey = crypto.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
        }
        else {
            throw new Error('Unsupported key derivation scheme');
        }
        var ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');
        var mac = ethUtil.keccak256(Buffer.concat([derivedKey.slice(16, 32), ciphertext]));
        if (mac.toString('hex') !== json.crypto.mac) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }
        var decipher = crypto.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'));
        var seed = runCipherBuffer(decipher, ciphertext);
        return new Wallet(seed);
    };
    /*
     * Based on https://github.com/ethereum/pyethsaletool/blob/master/pyethsaletool.py
     * JSON fields: encseed, ethaddr, btcaddr, email
     */
    Wallet.fromEthSale = function (input, password) {
        var json = typeof input === 'object' ? input : JSON.parse(input);
        var encseed = Buffer.from(json.encseed, 'hex');
        // key derivation
        var derivedKey = crypto.pbkdf2Sync(password, password, 2000, 32, 'sha256').slice(0, 16);
        // seed decoding (IV is first 16 bytes)
        // NOTE: crypto (derived from openssl) when used with aes-*-cbc will handle PKCS#7 padding internally
        //       see also http://stackoverflow.com/a/31614770/4964819
        var decipher = crypto.createDecipheriv('aes-128-cbc', derivedKey, encseed.slice(0, 16));
        var seed = runCipherBuffer(decipher, encseed.slice(16));
        var wallet = new Wallet(ethUtil.keccak256(seed));
        if (wallet.getAddress().toString('hex') !== json.ethaddr) {
            throw new Error('Decoded key mismatch - possibly wrong passphrase');
        }
        return wallet;
    };
    Object.defineProperty(Wallet.prototype, "pubKey", {
        // private getters
        get: function () {
            if (!keyExists(this.publicKey)) {
                this.publicKey = ethUtil.privateToPublic(this.privateKey);
            }
            return this.publicKey;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Wallet.prototype, "privKey", {
        get: function () {
            if (!keyExists(this.privateKey)) {
                throw new Error('This is a public key only wallet');
            }
            return this.privateKey;
        },
        enumerable: true,
        configurable: true
    });
    // public instance methods
    // tslint:disable-next-line
    Wallet.prototype.getPrivateKey = function () {
        return this.privKey;
    };
    Wallet.prototype.getPrivateKeyString = function () {
        return ethUtil.bufferToHex(this.privKey);
    };
    // tslint:disable-next-line
    Wallet.prototype.getPublicKey = function () {
        return this.pubKey;
    };
    Wallet.prototype.getPublicKeyString = function () {
        return ethUtil.bufferToHex(this.getPublicKey());
    };
    Wallet.prototype.getAddress = function () {
        return ethUtil.publicToAddress(this.pubKey);
    };
    Wallet.prototype.getAddressString = function () {
        return ethUtil.bufferToHex(this.getAddress());
    };
    Wallet.prototype.getChecksumAddressString = function () {
        return ethUtil.toChecksumAddress(this.getAddressString());
    };
    Wallet.prototype.toV3 = function (password, opts) {
        if (!keyExists(this.privateKey)) {
            throw new Error('This is a public key only wallet');
        }
        var v3Params = mergeToV3ParamsWithDefaults(opts);
        var kdfParams;
        var derivedKey;
        switch (v3Params.kdf) {
            case "pbkdf2" /* PBKDF */:
                kdfParams = kdfParamsForPBKDF(v3Params);
                derivedKey = crypto.pbkdf2Sync(Buffer.from(password), kdfParams.salt, kdfParams.c, kdfParams.dklen, 'sha256');
                break;
            case "scrypt" /* Scrypt */:
                kdfParams = kdfParamsForScrypt(v3Params);
                // FIXME: support progress reporting callback
                derivedKey = scryptsy(Buffer.from(password), kdfParams.salt, kdfParams.n, kdfParams.r, kdfParams.p, kdfParams.dklen);
                break;
            default:
                throw new Error('Unsupported kdf');
        }
        var cipher = crypto.createCipheriv(v3Params.cipher, derivedKey.slice(0, 16), v3Params.iv);
        if (!cipher) {
            throw new Error('Unsupported cipher');
        }
        var ciphertext = runCipherBuffer(cipher, this.privKey);
        var mac = ethUtil.keccak256(Buffer.concat([derivedKey.slice(16, 32), Buffer.from(ciphertext)]));
        return {
            version: 3,
            id: uuidv4({ random: v3Params.uuid }),
            // @ts-ignore - the official V3 keystore spec omits the address key
            address: this.getAddress().toString('hex'),
            crypto: {
                ciphertext: ciphertext.toString('hex'),
                cipherparams: { iv: v3Params.iv.toString('hex') },
                cipher: v3Params.cipher,
                kdf: v3Params.kdf,
                kdfparams: __assign(__assign({}, kdfParams), { salt: kdfParams.salt.toString('hex') }),
                mac: mac.toString('hex'),
            },
        };
    };
    Wallet.prototype.getV3Filename = function (timestamp) {
        /*
         * We want a timestamp like 2016-03-15T17-11-33.007598288Z. Date formatting
         * is a pain in Javascript, everbody knows that. We could use moment.js,
         * but decide to do it manually in order to save space.
         *
         * toJSON() returns a pretty close version, so let's use it. It is not UTC though,
         * but does it really matter?
         *
         * Alternative manual way with padding and Date fields: http://stackoverflow.com/a/7244288/4964819
         *
         */
        var ts = timestamp ? new Date(timestamp) : new Date();
        return ['UTC--', ts.toJSON().replace(/:/g, '-'), '--', this.getAddress().toString('hex')].join('');
    };
    Wallet.prototype.toV3String = function (password, opts) {
        return JSON.stringify(this.toV3(password, opts));
    };
    return Wallet;
}());
exports.default = Wallet;
// helpers
function runCipherBuffer(cipher, data) {
    return Buffer.concat([cipher.update(data), cipher.final()]);
}
function keyExists(k) {
    return k !== undefined && k !== null;
}
//# sourceMappingURL=index.js.map