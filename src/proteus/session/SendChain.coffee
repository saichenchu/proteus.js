# Wire
# Copyright (C) 2016 Wire Swiss GmbH
# Based on libsignal-protocol-java by Open Whisper Systems
# https://github.com/WhisperSystems/libsignal-protocol-java
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

CBOR = require 'wire-webapp-cbor'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

KeyPair = require '../keys/KeyPair'

ChainKey = require './ChainKey'

module.exports = class SendChain
  constructor: ->
    throw new DontCallConstructor @

  @new: (chain_key, keypair) ->
    TypeUtil.assert_is_instance ChainKey, chain_key
    TypeUtil.assert_is_instance KeyPair, keypair

    sc = ClassUtil.new_instance SendChain
    sc.chain_key = chain_key
    sc.ratchet_key = keypair
    return sc

  encode: (e) ->
    e.object 2
    e.u8 0; @chain_key.encode e
    e.u8 1; @ratchet_key.encode e

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance SendChain

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.chain_key   = ChainKey.decode d
        when 1 then self.ratchet_key = KeyPair.decode d
        else d.skip()

    TypeUtil.assert_is_instance ChainKey, self.chain_key
    TypeUtil.assert_is_instance KeyPair, self.ratchet_key

    return self
