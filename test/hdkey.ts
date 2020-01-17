import * as assert from 'assert'
import EthereumHDKey from '../src/hdkey'

// from BIP39 mnemonic: awake book subject inch gentle blur grant damage process float month clown
const fixtureseed = Buffer.from(
  '747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03',
  'hex',
)
const fixturehd = EthereumHDKey.fromMasterSeed(fixtureseed)

describe('.fromMasterSeed()', function() {
  it('should work', function() {
    assert.doesNotThrow(function() {
      EthereumHDKey.fromMasterSeed(fixtureseed)
    })
  })
})

describe('.privateExtendedKey()', function() {
  it('should work', function() {
    assert.strictEqual(
      fixturehd.privateExtendedKey(),
      'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY',
    )
  })
})

describe('.publicExtendedKey()', function() {
  it('should work', function() {
    assert.strictEqual(
      fixturehd.publicExtendedKey(),
      'xpub661MyMwAqRbcGout4B6s29b6gGQsowyoiF6UgXBEr7eFCWYfXuZDvRxP9zEh1Kwq3TLqDQMbkbaRpSnoC28oWvjLeshoQz1StZ9YHM1EpcJ',
    )
  })
})

describe('.fromExtendedKey()', function() {
  it('should work with public', function() {
    const hdnode = EthereumHDKey.fromExtendedKey(
      'xpub661MyMwAqRbcGout4B6s29b6gGQsowyoiF6UgXBEr7eFCWYfXuZDvRxP9zEh1Kwq3TLqDQMbkbaRpSnoC28oWvjLeshoQz1StZ9YHM1EpcJ',
    )
    assert.strictEqual(
      hdnode.publicExtendedKey(),
      'xpub661MyMwAqRbcGout4B6s29b6gGQsowyoiF6UgXBEr7eFCWYfXuZDvRxP9zEh1Kwq3TLqDQMbkbaRpSnoC28oWvjLeshoQz1StZ9YHM1EpcJ',
    )
    assert.throws(function() {
      hdnode.privateExtendedKey()
    }, /^Error: This is a public key only wallet$/)
  })
  it('should work with private', function() {
    const hdnode = EthereumHDKey.fromExtendedKey(
      'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY',
    )
    assert.strictEqual(
      hdnode.publicExtendedKey(),
      'xpub661MyMwAqRbcGout4B6s29b6gGQsowyoiF6UgXBEr7eFCWYfXuZDvRxP9zEh1Kwq3TLqDQMbkbaRpSnoC28oWvjLeshoQz1StZ9YHM1EpcJ',
    )
    assert.strictEqual(
      hdnode.privateExtendedKey(),
      'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY',
    )
  })
})

describe('.deriveChild()', function() {
  it('should work', function() {
    const hdnode = fixturehd.deriveChild(1)
    assert.strictEqual(
      hdnode.privateExtendedKey(),
      'xprv9vYSvrg3eR5FaKbQE4Ao2vHdyvfFL27aWMyH6X818mKWMsqqQZAN6HmRqYDGDPLArzaqbLExRsxFwtx2B2X2QKkC9uoKsiBNi22tLPKZHNS',
    )
  })
})

describe('.derivePath()', function() {
  it('should work with m', function() {
    const hdnode = fixturehd.derivePath('m')
    assert.strictEqual(
      hdnode.privateExtendedKey(),
      'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY',
    )
  })
  it("should work with m/44'/0'/0/1", function() {
    const hdnode = fixturehd.derivePath("m/44'/0'/0/1")
    assert.strictEqual(
      hdnode.privateExtendedKey(),
      'xprvA1ErCzsuXhpB8iDTsbmgpkA2P8ggu97hMZbAXTZCdGYeaUrDhyR8fEw47BNEgLExsWCVzFYuGyeDZJLiFJ9kwBzGojQ6NB718tjVJrVBSrG',
    )
  })
})
