"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("./index");
var HDKey = require('hdkey');
var EthereumHDKey = /** @class */ (function () {
    function EthereumHDKey(_hdkey) {
        this._hdkey = _hdkey;
    }
    EthereumHDKey.fromMasterSeed = function (seedBuffer) {
        return new EthereumHDKey(HDKey.fromMasterSeed(seedBuffer));
    };
    EthereumHDKey.fromExtendedKey = function (base58Key) {
        return new EthereumHDKey(HDKey.fromExtendedKey(base58Key));
    };
    EthereumHDKey.prototype.privateExtendedKey = function () {
        if (!this._hdkey.privateExtendedKey) {
            throw new Error('This is a public key only wallet');
        }
        return this._hdkey.privateExtendedKey;
    };
    EthereumHDKey.prototype.publicExtendedKey = function () {
        return this._hdkey.publicExtendedKey;
    };
    EthereumHDKey.prototype.derivePath = function (path) {
        return new EthereumHDKey(this._hdkey.derive(path));
    };
    EthereumHDKey.prototype.deriveChild = function (index) {
        return new EthereumHDKey(this._hdkey.deriveChild(index));
    };
    EthereumHDKey.prototype.getWallet = function () {
        if (this._hdkey._privateKey) {
            return index_1.default.fromPrivateKey(this._hdkey._privateKey);
        }
        return index_1.default.fromPublicKey(this._hdkey._publicKey, true);
    };
    return EthereumHDKey;
}());
exports.default = EthereumHDKey;
//# sourceMappingURL=hdkey.js.map