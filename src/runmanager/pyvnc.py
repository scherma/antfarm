#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

from vncdotool import client, api
from random import randrange
import sys, logging, time

logger = logging.getLogger(__name__)

class Connector:
    def __init__(self, address, password):
        self.address = address
        self.client = api.connect(address)
        self.pointer = (0,0)
        self.password = password

    def randomTime(self, basetime):
        r = float(randrange(-1000, 1000)) / 10000
        return basetime + r

    def singleKey(self, key):
        self.client.keyPress(key)
        self.client.pause(self.randomTime(0.3))

    def typestring(self, thestring, pause=True):
        for c in thestring:
            if c in u"¬!\"£$%^&*()_+QWERTYUIOP{}ASDFGHJKL:@~|ZXCVBNM<>?":
                self.client.keyDown("lshift")
                self.client.keyPress(c)
                self.client.keyUp("lshift")
            else:
                self.client.keyPress(c)
            if pause:
                self.client.pause(self.randomTime(0.2))
    
    def mouseMove(self, x, y):
        self.client.mouseMove(x, y)
        self.pointer = (x, y)

    def clickPos(self, x, y, button=1):
        # randomise target position by 2px
        h_adj = randrange(-2, 2, 1)
        w_adj = randrange(-2, 2, 1)
        self.mouseMove(x + h_adj, y + w_adj)
        self.client.pause(0.2)
        self.client.mousePress(button)
        self.client.pause(0.3)

    def startMenu(self):
        self.clickPos(25, 1033)
        self.client.pause(self.randomTime(0.4))

    def allPrograms(self):
        self.clickPos(71, 942)
        self.client.pause(self.randomTime(0.4))

    def msOffice(self):
        self.clickPos(72, 825)
        self.client.pause(self.randomTime(0.4))

    def msWord(self):
        self.clickPos(108, 895)
        self.client.pause(self.randomTime(3))

    def iExplore(self):
        #self.clickPos(84, 1038)
        self.singleKey("lsuper")
        self.client.pause(self.randomTime(1))
        self.typestring("internet explorer")
        self.singleKey("enter")
        self.client.pause(self.randomTime(3))

    def iExploreAddressBar(self):
        self.clickPos(212, 42)
        self.client.pause(self.randomTime(0.4))

    def goToIEPage(self, address):
        self.iExplore()
        self.typestring(address)
        self.singleKey('enter')
        self.client.pause(2)

    def closeIE(self):
        self.clickPos(85, 1032, button=3)
        self.client.pause(self.randomTime(1))
        self.clickPos(91, 991)
        self.client.pause(self.randomTime(1))

    def launchCMD(self):
        logger.debug("Launching CMD window")
        self.client.keyPress('lsuper')
        self.client.pause(self.randomTime(1))
        self.typestring('cmd')
        self.client.keyDown('ctrl')
        self.client.keyDown('lshift')
        self.client.keyPress('enter')
        self.client.keyUp('lshift')
        self.client.keyUp('ctrl')
        self.client.pause(self.randomTime(0.5))
        self.singleKey('left')
        self.singleKey('enter')
        self.client.pause(self.randomTime(2))
        
    def bank(self):
        self.goToIEPage("www.hsbc.co.uk")
        self.client.pause(self.randomTime(10))
        self.clickPos(1208, 74)
        self.client.pause(self.randomTime(14))
        self.typestring("jhorner1986")
        self.client.pause(self.randomTime(2))
        self.clickPos(633, 411)
        self.client.pause(self.randomTime(6))
        self.closeIE()
        
    def web(self):
        pass

    def downloadAndRun(self, filename):
        logger.debug("Running file {0}".format(filename))
        self.client.keyDown("lsuper")
        self.client.keyPress("r")
        self.client.keyUp("lsuper")
        self.client.pause(2)
        self.typestring('powershell -executionPolicy bypass -file "C:\\Program Files\\run.ps1" "{0}"'.format(filename))
        self.client.keyPress("enter")
        self.client.pause(2)
        self.clickPos(934, 364)
        self.client.pause(1)
        self.clickPos(1015, 383)
        self.client.pause(12)
        
        self.singleKey("enter")
        self.singleKey("enter")
                
        self.clickPos(1120, 988)
        self.client.pause(self.randomTime(3))
        self.closeIE()
        
    def restart(self):
        self.startMenu()
        self.client.pause(self.randomTime(1))
        self.clickPos(350, 980)
        self.client.pause(self.randomTime(1))
        self.clickPos(410, 955)
        # reboot takes approx 25 seconds - disconnect first or Twisted throws a hissy fit
        self.disconnect()
        time.sleep(45)
        self.client = api.connect(self.address)
        self.clickPos(797, 636)
        self.typestring(self.password)
        self.singleKey("enter")
        self.client.pause(self.randomTime(10))

    def prepVM(self, date, time):
        logger.debug("Preparing VM with date and time")
        self.launchCMD()
        self.typestring("date {0}".format(date))
        self.singleKey('enter')
        self.typestring("time {0}".format(time))
        self.singleKey('enter')
        self.typestring('exit')
        self.singleKey('enter')
        
    def basic(self):
        self.mouseMove(110,948)
        self.client.pause(self.randomTime(1))
        
        self.clickPos(26, 1034)
        self.client.pause(self.randomTime(2))
        self.typestring("microsoft word")
        self.singleKey("enter")
        self.client.pause(self.randomTime(2))
        self.typestring("I've got a lovely bunch of coconuts")
        self.singleKey("enter")
        self.singleKey("enter")
        self.client.pause(self.randomTime(4))
        self.clickPos(1672, 17)
        self.client.pause(self.randomTime(2))
        self.singleKey("n")
        self.mouseMove(127, 909)
        self.mouseMove(1462, 932)
        self.client.pause(self.randomTime(8))
        self.mouseMove(1137, 604)
        self.mouseMove(479, 616)
        self.mouseMove(473, 669)
        self.mouseMove(617, 698)
        self.client.pause(self.randomTime(6))
        self.mouseMove(33, 1036)
        
    def closeWindow(self):
        self.client.keyDown('alt')
        self.singleKey('f4')
        self.client.keyUp('alt')

    def disconnect(self):
        self.client.disconnect()

#c = Connector("127.0.0.1::5900")

#c.prepVM('08/04/2017', '22:50:53')
#c.downloadAndRun('pafish.exe')
#c.closeWindow()
