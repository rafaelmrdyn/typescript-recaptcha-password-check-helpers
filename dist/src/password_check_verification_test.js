"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
require("jasmine");
const ec_commutative_cipher_1 = require("./emscripten/ec_commutative_cipher");
const ec_commutative_cipher_impl_1 = require("./emscripten/ec_commutative_cipher_impl");
const node_crypto_1 = require("node:crypto");
const password_check_verification_1 = require("./password_check_verification");
const crypto_helper_1 = require("./utils/crypto_helper");
describe('password check verification test', () => {
    it('creates a password check verification', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        expect(verification.getUsername()).toBe(TEST_USERNAME);
        expect(verification.getEncryptedUserCredentialsHash().length)
            .toBeGreaterThan(0);
        expect(verification.getLookupHashPrefix().length).toBeGreaterThan(0);
    }));
    it('password check response is well formed', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        const serverResponse = yield TestServerResponse.create(verification, TEST_MATCHING_USERNAME_LIST);
        const passwordCheckResponse = yield verification.verify(serverResponse.getServerReencryptedLookupHash(), serverResponse.getEncryptedLeakMatchPrefixTestList());
        expect(passwordCheckResponse.getUsername()).toBe(TEST_USERNAME);
        expect(passwordCheckResponse.getVerification()).toEqual(verification);
        expect(passwordCheckResponse.areCredentialsLeaked()).toBeTrue();
    }));
    it('throws if username is empty', () => __awaiter(void 0, void 0, void 0, function* () {
        yield expectAsync(password_check_verification_1.PasswordCheckVerification.create('', TEST_PASSWORD))
            .toBeRejectedWithError('Username cannot be null or empty');
    }));
    it('throws if password is empty', () => __awaiter(void 0, void 0, void 0, function* () {
        yield expectAsync(password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, ''))
            .toBeRejectedWithError('Password cannot be null or empty');
    }));
    it('returns leak found', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        const response = yield TestServerResponse.create(verification, TEST_MATCHING_USERNAME_LIST);
        expect(response.checkCredentialsLeaked(verification)).toBeTrue();
    }));
    it('canonicalizes the username', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME + '@example.com', TEST_PASSWORD);
        const response = yield TestServerResponse.create(verification, TEST_MATCHING_USERNAME_LIST);
        expect(response.checkCredentialsLeaked(verification)).toBeTrue();
    }));
    it('returns not leak found', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        const response = yield TestServerResponse.create(verification, TEST_NOT_MATCHING_USERNAME_LIST);
        expect(response.checkCredentialsLeaked(verification)).toBeFalse();
    }));
    it('returns not leak found when empty list of prefixes is given', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        const response = yield TestServerResponse.create(verification, []);
        expect(response.checkCredentialsLeaked(verification)).toBeFalse();
    }));
    it('throws exception when encrypted user credentials hash is empty', () => __awaiter(void 0, void 0, void 0, function* () {
        const verification = yield password_check_verification_1.PasswordCheckVerification.create(TEST_USERNAME, TEST_PASSWORD);
        expect(() => verification.verify(new Uint8Array(0), [Uint8Array.of(1)]))
            .toThrow();
    }));
});
// ============= Utility classes & constants ===================
class Credentials {
    constructor(username, password) {
        this.username = username;
        this.password = password;
    }
}
class TestServerResponse {
    constructor(serverReEncryptedLookupHash, encryptedLeakMatchPrefixTestList) {
        this.serverReEncryptedLookupHash = serverReEncryptedLookupHash;
        this.encryptedLeakMatchPrefixTestList = encryptedLeakMatchPrefixTestList;
    }
    static create(verification, credentialsList) {
        return __awaiter(this, void 0, void 0, function* () {
            const crypto = yield ec_commutative_cipher_impl_1.EcCommutativeCipherImpl.createEcCommutativeCipherImpl();
            const serverCipher = ec_commutative_cipher_1.EcCommutativeCipher.create(crypto, password_check_verification_1.PasswordCheckVerification.CURVE_ID, password_check_verification_1.PasswordCheckVerification.HASH_TYPE);
            const encryptedUserCredentialsHash = serverCipher.reencrypt(verification.getEncryptedUserCredentialsHash());
            const encryptedLeakMatchPrefixTestList = [];
            for (const credentials of credentialsList) {
                const prefix = (yield TestServerResponse.serverEncryptAndRehash(serverCipher, credentials))
                    .subarray(0, 20);
                encryptedLeakMatchPrefixTestList.push(prefix);
            }
            return new TestServerResponse(encryptedUserCredentialsHash, encryptedLeakMatchPrefixTestList);
        });
    }
    checkCredentialsLeaked(verification) {
        return verification
            .verify(this.serverReEncryptedLookupHash, this.encryptedLeakMatchPrefixTestList)
            .areCredentialsLeaked();
    }
    getServerReencryptedLookupHash() {
        return this.serverReEncryptedLookupHash;
    }
    getEncryptedLeakMatchPrefixTestList() {
        return this.encryptedLeakMatchPrefixTestList;
    }
    static serverEncryptAndRehash(serverCipher, credentials) {
        return __awaiter(this, void 0, void 0, function* () {
            const serverEncrypted = serverCipher.encrypt(yield crypto_helper_1.CryptoHelper.hashUsernamePasswordPair(credentials.username, credentials.password));
            return (0, node_crypto_1.createHash)('sha256').update(serverEncrypted).digest();
        });
    }
}
const TEST_USERNAME = 'foo';
const TEST_PASSWORD = 'bar';
const TEST_MATCHING_USERNAME_LIST = [
    new Credentials(TEST_USERNAME, TEST_PASSWORD), new Credentials('baz', 'pass')
];
const TEST_NOT_MATCHING_USERNAME_LIST = [new Credentials('foo', 'diff_password'), new Credentials('baz', 'pass')];
