/*

The MIT License (MIT)

Copyright (c) 2015 Chris Corbyn.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

'use strict';

var util = require('util');

/**
 * Representation of an IPv4 address or CIDR.
 *
 * For convenience, this constructor may be invoked as a regular function.
 *
 * @constructor
 *
 * @param {Object} address
 *   either a string or an integer
 *
 * @param {Number} prefix, optional
 *   the length of the netmask prefix
 *
 * @throws {Error}
 *   if the address is not valid
 */
module.exports.Addr = function Addr(address, prefix) {
  if (! (this && this.constructor === Addr)) {
    return new Addr(address, prefix);
  }

  var self = this
    /*! The address used when not specified */
    , DEFAULT_ADDRESS = 0
    /*! The prefix length used when not specified */
    , DEFAULT_PREFIX = 32
    /*! The lowest permissible address */
    , MIN_ADDRESS = 0
    /*! The highest permissible address */
    , MAX_ADDRESS = 0xFFFFFFFF
    ;

  /**
   * Replace this Addr with an new value.
   *
   * @param {Object} address
   *   either a string or an integer
   *
   * @param {Number} prefix, optional
   *   the length of the netmask prefix
   *
   * @return {Addr}
   *   returns `this` so operations can be chained
   *
   * @throws {Error}
   *   if the address if not valid
   */
  self.set = function(address, prefix) {
    try {
      switch (typeof address) {
        case 'undefined':
          return self.set(DEFAULT_ADDRESS, prefix);

        case 'string':
          return parseString(address, prefix);

        case 'number':
          return parseNumber(address, prefix);

        default:
          throw new Error(
            util.format(
              'Invalid Addr type: %s',
              (typeof address)
            )
          );
      }
    } catch (e) {
      throw new Error(util.format('Invalid Addr: %s', address));
    }
  };

  /**
   * Return true if the other Addr is equivalent to this.
   *
   * @param {Addr} other
   *   the other Addr to compare with
   *
   * @return {Boolean}
   *   true if the other Addr is the same
   */
  self.equals = function(other){
    if (other.toInt) {
      return self.toInt() == other.toInt() && self.prefix == other.prefix;
    } else {
      return false;
    }
  };

  /**
   * Return the string representation of this Addr.
   *
   * @return {String}
   *   the string representation, including the mask
   */
  self.toString = function() {
    return [
      self.octets.join('.'),
      self.prefix
    ].join('/');
  };

  /**
   * Return the integer representation of this Addr.
   *
   * @return {Number}
   *   the integer value of the Addr
   */
  self.toInt = function() {
    return self.intval;
  };

  /**
   * Mask this address with a new prefix length.
   *
   * This method normalizes the underlying address to match the prefix.
   *
   * @param {Number} prefix
   *   the new prefix length
   *
   * @return {Addr}
   *   the address with the new mask
   */
  self.mask = function(prefix) {
    return new Addr(
      new Addr(self.toInt(), prefix).network().toInt(),
      prefix
    );
  };

  /**
   * Return the netmask value for this Addr.
   *
   * @return {Addr}
   *   the netmask
   */
  self.netmask = function() {
    switch (self.prefix) {
      case 0:
        return new Addr(0x00000000);

      case 32:
        return new Addr(0xFFFFFFFF);

      default:
        return new Addr(~(0xFFFFFFFF >>> self.prefix) >>> 0);
    }
  };

  /**
   * Return the network address from this Addr.
   *
   * This equates to the first address in the CIDR range.
   *
   * @return {Addr}
   *   the network address
   */
  self.network = function() {
    return new Addr((self.toInt() & self.netmask().toInt()) >>> 0);
  };

  /**
   * Return the broadcast address from this Addr.
   *
   * This equates to the last address in the CIDR range.
   *
   * @return {Number}
   *   the broadcast address
   */
  self.broadcast = function() {
    return new Addr((self.network().toInt() | ~self.netmask().toInt()) >>> 0);
  };

  /**
   * Return true if this Addr completely contains another Addr.
   *
   * @param {Addr} other
   *   the other Addr to check
   *
   * @return {Boolean}
   *   true if other is a subset of this, false if not
   */
  self.contains = function(other) {
    return onNetwork(other.network()) && onNetwork(other.broadcast());
  };

  /**
   * Return the CIDR range that is the intersection of `this` and `other`.
   *
   * Because CIDR subnets cannot possibly partially overlap, in practice this
   * method returns either `this` or `other` where there is a match. The
   * returned Addr will always be the smallest range.
   *
   * @param {Addr} other
   *   another Addr to intersect with
   *
   * @return {Addr}
   *   the intersection of the two Addrs, or undefined if not possible
   */
  self.intersect = function(other) {
    return (self.contains(other) && other)
      || (other.contains(self) && self)
      || undefined
      ;
  };

  /**
   * Increment this address by 1 and return a new Addr.
   *
   * @return {Addr}
   *   the next address in sequence
   *
   * @throws {Error}
   *   if already the max address
   */
  self.increment = function() {
    if (self.toInt() < MAX_ADDRESS) {
      return new Addr(self.toInt() + 1, self.prefix);
    } else {
      throw new Error(
        util.format(
          'Cannot increment %s: already the max value',
          self
        )
      );
    }
  };

  /**
   * Decrement this address by 1 and return a new Addr.
   *
   * @return {Addr}
   *   the previous address in sequence
   *
   * @throws {Error}
   *   if already the min address
   */
  self.decrement = function() {
    if (self.toInt() > MIN_ADDRESS) {
      return new Addr(self.toInt() - 1, self.prefix);
    } else {
      throw new Error(
        util.format(
          'Cannot decrement %s: already the min value',
          self
        )
      );
    }
  };

  /**
   * Get the next adjacent subnet to this one.
   *
   * @return {Addr}
   *   the adjacent subnet, with the same prefix
   *
   * @throws {Error}
   *   if it is not possible to increment this subnet
   */
  self.nextSibling = function() {
    return self.broadcast().increment().mask(self.prefix);
  };

  /**
   * Get the previous adjacent subnet to this one.
   *
   * @return {Addr}
   *   the adjacent subnet, with the same prefix
   *
   * @throws {Error}
   *   if it is not possible to decrement this subnet
   */
  self.prevSibling = function() {
    return self.network().decrement().mask(self.prefix);
  };

  /*! Set the initial value */
  self.set(address, prefix);

  // -- Private

  /*! Convert the given octets to an integer */
  function octetsToInt(octets) {
    return Array.apply([], octets)
      .reverse()
      .map(function(octet, offset){
        return octet * (1 << offset * 8);
      })
      .reduce(function(x, y){
        return x + y;
      });
  }

  /*! Set the internal parsed structures */
  function setInternal(octets, prefix) {
    setProperty('intval', octetsToInt(octets));
    setProperty('octets', octets);
    setProperty('prefix', prefix);
    return self;
  }

  /*! Define a read-only property */
  function setProperty(key, value) {
    Object.defineProperty(self, key, {value: value, enumerable: true});
  }

  /*! Parse an IPv4 address string with optional prefix */
  function parseString(address, prefix) {
    var parts = address.split('/')
      , prefix = (
        typeof prefix == 'undefined'
          ? (parts[1] || DEFAULT_PREFIX)
          : prefix
      );

    if (parts.length > 2) {
      throw new Error(util.format('Invalid Addr: %s', address));
    }

    return setInternal(
      parts[0].split('.').map(function(n){
        return parseByte(n, 255)
      }),
      parseByte(prefix, 32)
    );
  }

  /*! Parse an IPv4 address integer with optional prefix */
  function parseNumber(address, prefix) {
    var prefix = (
        typeof prefix == 'undefined'
          ? DEFAULT_PREFIX
          : prefix
      );

    if (address > MAX_ADDRESS || address < MIN_ADDRESS) {
      throw new Error(util.format('Invalid Addr: %s', address));
    }

    return setInternal(
      [255, 255, 255, 255]
        .map(function(octet, offset){
          return (address >>> (offset * 8)) & octet;
        })
        .reverse(),
      parseByte(prefix, 32)
    );
  }

  /*! Return true if a fixed IP is on this network */
  function onNetwork(ip) {
    return (self.netmask().toInt() & ip.toInt()) >>> 0 == self.network().toInt();
  }
};

/**
 * Perform a parseInt(), only if a valid byte value with an optional max.
 *
 * @param {String} n
 *   the value to parse
 *
 * @param {Number} max
 *   the maximum allowed value
 *
 * @return {Number}
 *   the parsed integer
 */
function parseByte(n, max) {
  max = max || 255;

  if (/^[0-9]+$/.test(n)) {
    var m = parseInt(n);
    if (m <= max) {
      return m;
    }
  }

  throw new Error(
    util.format(
      '%s: must be a decimal value <= %d',
      n,
      max
    )
  );
}
