'use strict';

var assert = require('assert')
  , Addr = require('../lib/addrv4').Addr
  ;

describe('addrv4', function(){
  describe('constructor', function(){
    describe('with a valid dotted IP', function(){
      it('succeeds', function(){
        assert(Addr('1.1.1.1'));
      });
    });

    describe('with a valid CIDR', function(){
      it('succeeds', function(){
        assert(Addr('1.1.1.1/8'));
      });
    });

    describe('with a valid integer', function(){
      it('succeeds', function(){
        assert(Addr(128));
      });
    });

    describe('with an invalid byte', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr('1.256.1.1'); });
      });
    });

    describe('with a cidr prefix out of range', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr('1.1.1.1/35'); });
      });
    });

    describe('with a negative integer', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr(-128); });
      });
    });

    describe('with a 64 bit integer', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr(0xFFFFFFFF + 1); });
      });
    });

    describe('with a negative prefix', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr(256, -24); });
      });
    });

    describe('with a prefix more than 32 bits', function(){
      it('throws an error', function(){
        assert.throws(function(){ Addr(256, 35); });
      });
    });
  });

  describe('#octets', function(){
    describe('with a string', function(){
      it('returns the parsed octets', function(){
        assert.deepEqual([10, 0, 52, 138], Addr('10.0.52.138').octets);
      });
    });

    describe('with a number', function(){
      it('returns the computed octets', function(){
        assert.deepEqual([127, 0, 0, 1], Addr(2130706433).octets);
      });
    });
  });

  describe('#prefix', function(){
    describe('when part of the cidr', function(){
      it('returns the decimal value', function(){
        assert.equal(24, Addr('1.1.1.1/24').prefix);
      });
    });

    describe('when explicitly provided', function(){
      it('returns the decimal value', function(){
        assert.equal(22, Addr('1.1.1.1/24', 22).prefix);
      });
    });

    describe('when unspecified', function(){
      it('returns 32', function(){
        assert.equal(32, Addr('1.1.1.1').prefix);
      });
    });
  });

  describe('#toInt()', function(){
    it('returns the numeric value', function(){
      assert.deepEqual(2130706433, Addr('127.0.0.1').toInt());
    });
  });

  describe('#toString()', function(){
    it('returns the dotted notation with the prefix', function(){
      assert.equal('127.0.0.1/18', Addr(2130706433, 18).toString());
    });
  });

  describe('#mask()', function(){
    it('returns the address masked with a new prefix', function(){
      assert.equal('10.1.0.0/16', Addr('10.1.3.57/32').mask(16).toString());
    });
  });

  describe('#equals', function(){
    describe('with the same address and prefix', function(){
      it('returns true', function(){
        assert(
          Addr('127.0.0.1/16')
            .equals(Addr(2130706433, 16))
        );
      });
    });

    describe('with a different address', function(){
      it('returns false', function(){
        assert(
          !Addr('127.0.0.1/16')
            .equals(Addr(2000000000, 16))
        );
      });
    });

    describe('with a different prefix', function(){
      it('returns false', function(){
        assert(
          !Addr('127.0.0.1/16')
            .equals(Addr(2130706433, 15))
        );
      });
    });

    describe('with a non Addr', function(){
      it('returns false', function(){
        assert(!Addr('127.0.0.1/16').equals(42));
      });
    });
  });

  describe('#netmask()', function(){
    describe('at prefix zero', function(){
      it('returns the Addr of the mask', function(){
        assert.equal(
          '0.0.0.0/32',
          Addr('1.1.1.1/0').netmask().toString()
        );
      });
    });

    describe('at prefix 32', function(){
      it('returns the Addr of the mask', function(){
        assert.equal(
          '255.255.255.255/32',
          Addr('1.1.1.1/32').netmask().toString()
        );
      });
    });

    describe('at prefix 1-31', function(){
      it('returns the Addr of the mask', function(){
        assert.equal(
          '255.255.252.0/32',
          Addr('1.1.1.1/22').netmask().toString()
        );
      });
    });
  });

  describe('#network()', function(){
    describe('at prefix zero', function(){
      it('returns the Addr of the network', function(){
        assert.equal(
          '0.0.0.0/32',
          Addr('1.1.1.1/0').network().toString()
        );
      });
    });

    describe('at prefix 32', function(){
      it('returns the Addr of the network', function(){
        assert.equal(
          '1.1.1.1/32',
          Addr('1.1.1.1/32').network().toString()
        );
      });
    });

    describe('at prefix 1-31', function(){
      it('returns the Addr of the network', function(){
        assert.equal(
          '10.3.0.0/32',
          Addr('10.3.0.1/16').network().toString()
        );
      });
    });
  });

  describe('#broadcast', function(){
    describe('at prefix zero', function(){
      it('returns the Addr of the broadcast address', function(){
        assert.equal(
          '255.255.255.255/32',
          Addr('1.1.1.1/0').broadcast().toString()
        );
      });
    });

    describe('at prefix 32', function(){
      it('returns the Addr of the broadcast address', function(){
        assert.equal(
          '1.1.1.1/32',
          Addr('1.1.1.1/32').broadcast().toString()
        );
      });
    });

    describe('at prefix 1-31', function(){
      it('returns the Addr of the broadcast address', function(){
        assert.equal(
          '10.3.255.255/32',
          Addr('10.3.0.1/16').broadcast().toString()
        );
      });
    });
  });

  describe('#contains()', function(){
    describe('with an Addr inside the network range', function(){
      it('returns true', function(){
        assert(Addr('192.168.1.0/16').contains(Addr('192.168.3.0/24')));
      });
    });

    describe('with an Addr larger than the network range', function(){
      it('returns false', function(){
        assert(!Addr('192.168.1.0/24').contains(Addr('192.168.1.0/16')));
      });
    });

    describe('with an Addr outside the network range', function(){
      it('returns false', function(){
        assert(!Addr('192.168.1.0/24').contains(Addr('192.168.2.0/24')));
      });
    });
  });

  describe('#intersect()', function(){
    describe('with an Addr inside the network range', function(){
      it('returns the other Addr', function(){
        assert.equal(
          '10.0.3.0/24',
          Addr('10.0.0.0/16').intersect(Addr('10.0.3.0/24')).toString()
        );
      });
    });

    describe('with an Addr larger than the network range', function(){
      it('returns self', function(){
        assert.equal(
          '10.0.3.0/24',
          Addr('10.0.3.0/24').intersect(Addr('10.0.0.0/16')).toString()
        );
      });
    });

    describe('with an Addr outside the network range', function(){
      it('returns undefined', function(){
        assert.equal(
          'undefined',
          typeof Addr('10.0.0.0/24').intersect(Addr('10.3.0.0/24'))
        );
      });
    });
  });

  describe('#increment()', function(){
    describe('with the maximum address', function(){
      it('throws an error', function(){
        assert.throws(function(){
          Addr('255.255.255.255/24').increment();
        });
      });
    });

    describe('with an incrementable address', function(){
      it('returns the next address', function(){
        assert.equal(
          '10.0.2.0/24',
          Addr('10.0.1.255/24').increment().toString()
        );
      });
    });
  });

  describe('#decrement()', function(){
    describe('with the minimum address', function(){
      it('throws an error', function(){
        assert.throws(function(){
          Addr('0.0.0.0/24').decrement();
        });
      });
    });

    describe('with an decrementable address', function(){
      it('returns the previous address', function(){
        assert.equal(
          '10.0.1.255/24',
          Addr('10.0.2.0/24').decrement().toString()
        );
      });
    });
  });

  describe('#nextSibling()', function(){
    it('returns adjacent subnet', function(){
      assert.equal(
        '10.2.0.0/16',
        Addr('10.1.0.0/16').nextSibling().toString()
      );
    });
  });

  describe('#prevSibling()', function(){
    it('returns adjacent subnet', function(){
      assert.equal(
        '9.255.0.0/16',
        Addr('10.0.0.0/16').prevSibling().toString()
      );
    });
  });
});
