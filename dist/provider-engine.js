"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var HookedWalletEthTxSubprovider = require('web3-provider-engine/subproviders/hooked-wallet-ethtx');
var WalletSubprovider = /** @class */ (function (_super) {
    __extends(WalletSubprovider, _super);
    function WalletSubprovider(wallet, opts) {
        var _this = this;
        if (!opts) {
            opts = {};
        }
        opts.getAccounts = function (cb) { return cb(null, [wallet.getAddressString()]); };
        opts.getPrivateKey = function (address, cb) {
            if (address !== wallet.getAddressString()) {
                cb(new Error('Account not found'));
            }
            else {
                cb(null, wallet.getPrivateKey());
            }
        };
        _this = _super.call(this, opts) || this;
        return _this;
    }
    return WalletSubprovider;
}(HookedWalletEthTxSubprovider));
exports.default = WalletSubprovider;
//# sourceMappingURL=provider-engine.js.map