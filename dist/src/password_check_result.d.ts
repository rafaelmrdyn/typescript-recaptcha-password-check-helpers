/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { PasswordCheckVerification } from './password_check_verification';
/**
 * PasswordCheckResult
 */
export declare class PasswordCheckResult {
    private readonly verification;
    private readonly username;
    private readonly credentialsLeaked;
    /**
     * Creates a new PasswordCheckResult
     */
    constructor(verification: PasswordCheckVerification, username: string, credentialsLeaked: boolean);
    /**
     * Returns the PasswordCheckVerification associated to this instance.
     */
    getVerification(): PasswordCheckVerification;
    /**
     * Returns the username associated to this instance.
     */
    getUsername(): string;
    /**
     * Returns whether or not credentials were leaked in the associated
     * verification.
     */
    areCredentialsLeaked(): boolean;
}
