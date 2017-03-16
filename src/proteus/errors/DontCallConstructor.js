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

const extend = function(child, parent) {
  for (let key in parent) {
    if ({}.hasOwnProperty.call(parent, key)) child[key] = parent[key];
  }
  const ctor = function() {
    this.constructor = child;
  };
  ctor.prototype = parent.prototype;
  child.prototype = new ctor();
  child.__super__ = parent.prototype;
  return child;
};

module.exports = (function(superClass) {
  extend(DontCallConstructor, superClass);

  function DontCallConstructor(_instance) {
    this._instance = _instance;
    DontCallConstructor.__super__.constructor.call(this,
      `Instead of 'new {this._instance.constructor.name}', use '${this._instance.constructor.name}.new'.`
    );
  }

  return DontCallConstructor;
})(ProteusError);
