/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const ProteusError = require('./ProteusError');

/** @module errors */

/** @extends ProteusError */
const DecryptError = class DecryptError extends ProteusError {
  /** @param message {string} */
  constructor(message = 'Unknown decryption error') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class RemoteIdentityChanged extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Remote identity changed') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class InvalidSignature extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Invalid signature') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class InvalidMessage extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Invalid message') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class DuplicateMessage extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Duplicate message') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class TooDistantFuture extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Message is from too distant in the future') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class OutdatedMessage extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Outdated message') {
    super();
    this.message = message;
  }
};

/** @extends DecryptError */
class PrekeyNotFound extends DecryptError {
  /** @param message {string} */
  constructor(message = 'Pre-key not found') {
    super();
    this.message = message;
  }
};

module.exports = ProteusError.DecryptError = DecryptError;
