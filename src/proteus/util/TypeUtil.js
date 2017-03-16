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

/** @module util */

const TypeUtil = {
  /**
   * @param classes {*}
   * @param inst {*}
   */
  assert_is_instance(classes, inst) {
    if (!Array.isArray(classes)) {
      classes = [classes];
    }
    if (classes.some((k) => inst instanceof k || (inst && inst.prototype instanceof k))) {
      return;
    }
    const valid_types = classes.map((k) => `'${k.name}'`).join(' or ');
    if (inst) {
      throw TypeError(`Expected one of ${valid_types}, got '${inst.constructor.name}'.`);
    }
    throw TypeError(`Expected one of ${valid_types}, got '${String(inst)}'.`);
  },
  /**
   * @param inst {*}
   * @returns {boolean}
   */
  assert_is_integer(inst) {
    if (Number.isInteger(inst)) {
      return true;
    }
    if (inst) {
      throw new TypeError(`Expected integer, got '${inst.constructor.name}'.`);
    }
    throw new TypeError(`Expected integer, got '${String(inst)}'.`);
  }
};

module.exports = TypeUtil;
