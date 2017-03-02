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

const ClassUtil = require('../util/ClassUtil');
const ProteusError = require('./ProteusError');

const DecodeError = class DecodeError extends ProteusError {
  constructor(message = 'Unknown decoding error') {
    super();
    this.message = message;
  }
}

DecodeError.InvalidType = class InvalidType extends DecodeError {
  constructor(message = 'Invalid type') {
    super();
    this.message = message;
  }
}

DecodeError.InvalidArrayLen = class InvalidArrayLen extends DecodeError {
  constructor(message = 'Invalid array length') {
    super();
    this.message = message;
  }
}

DecodeError.LocalIdentityChanged = class LocalIdentityChanged extends DecodeError {
  constructor(message = 'Local identity changed') {
    super();
    this.message = message;
  }
}

module.exports = ProteusError.DecodeError = DecodeError;
