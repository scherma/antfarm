#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

from vncdotool import client, api
from random import randrange, randint
import sys, logging, time

logger = logging.getLogger(__name__)

class Connector:
    def __init__(self, address, password, resolution):
        self.address = address
        self.client = api.connect(address)
        self.x = resolution[0]
        self.y = resolution[1]
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
            if c in "¬!\"£$%^&*()_+QWERTYUIOP{}ASDFGHJKL:@~|ZXCVBNM<>?":
                self.client.keyDown("lshift")
                self.client.keyPress(c)
                self.client.keyUp("lshift")
            else:
                self.client.keyPress(c)
            if pause:
                self.client.pause(self.randomTime(0.1))
    
    def mouseMove(self, x, y):
        self.client.mouseMove(x, y)
        self.pointer = (x, y)
        
    def randomMouseMove(self):
        x = randint(0, self.x)
        y = randint(0, self.y)
        self.mouseMove(x, y)

    def clickPos(self, x, y, button=1):
        # randomise target position by 2px
        h_adj = randrange(-2, 2, 1)
        w_adj = randrange(-2, 2, 1)
        self.mouseMove(x + h_adj, y + w_adj)
        self.client.pause(0.2)
        self.client.mousePress(button)
        self.client.pause(0.3)

    def iExplore(self):
        logger.debug("Launching Internet Explorer...")
        self.singleKey("lsuper")
        self.client.pause(self.randomTime(1))
        self.typestring("internet explorer")
        self.singleKey("enter")
        self.client.pause(self.randomTime(3))

    def goToIEPage(self, address):
        logger.debug("Opening IE with page {0}".format(address))
        self.iExplore()
        self.typestring(address)
        self.singleKey('enter')
        self.client.pause(2)

    def launchCMD(self):
        logger.debug("Launching CMD window")
        self.client.keyPress('lsuper')
        self.client.pause(self.randomTime(1))
        self.typestring('cmd')
        # shortcut to launch as administrator
        self.client.keyDown('ctrl')
        self.client.keyDown('lshift')
        self.client.keyPress('enter')
        self.client.keyUp('lshift')
        self.client.keyUp('ctrl')
        # give enough time for UAC to kick in
        self.client.pause(self.randomTime(2))
        # confirm UAC prompt
        self.singleKey('left')
        self.singleKey('enter')
        self.client.pause(self.randomTime(2))
        
    def bank(self):
        logger.debug("Visiting a banking site...")
        self.goToIEPage("www.hsbc.co.uk")
        self.client.pause(self.randomTime(10))
        # login button is 10 tabs after page load
        for i in range(0,10):
            self.singleKey("tab")
        self.singleKey("enter")
        self.client.pause(self.randomTime(14))
        self.typestring("jhorner1986")
        self.client.pause(self.randomTime(2))
        self.singleKey("tab")
        self.singleKey("enter")
        self.client.pause(self.randomTime(6))
        self.closeWindow()
        
    def mouseRand(self):
        x = randint(0, self.x)
        y = randint(0, self.y)
        
        
    def web(self):
        pass

    def downloadAndRun(self, foldername, filename, ext):
        logger.debug("Launching run window with WIN+R...")
        self.client.keyDown("lsuper")
        self.client.keyPress("r")
        self.client.keyUp("lsuper")
        self.client.pause(2)
        cmdstr = 'powershell -executionPolicy bypass -windowstyle hidden -file "C:\\Program Files\\run.ps1" "{}" "{}"'.format(filename, foldername)
        logger.debug("Powershell command: {0}".format(cmdstr))
        self.typestring(cmdstr)
        self.client.keyPress("enter")
        self.client.pause(2)
        if ext in ["exe"]:
            self.client.keyPress('r')
        elif ext in ["jse", "js", "vbe", "vbs", "wsf", "wsh"]:
            self.client.keyPress('o')
        
    def restart(self):
        # start menu, right for shutdown, right for context menu, up one for restart
        logger.debug("Selecting reboot option from start menu")
        self.singleKey("lsuper")
        self.client.pause(self.randomTime(1))
        self.singleKey("right")
        self.client.pause(self.randomTime(1))
        self.singleKey("right")
        self.client.pause(self.randomTime(1))
        self.singleKey("up")
        self.client.pause(self.randomTime(1))
        self.singleKey("enter")
        # reboot takes approx 25 seconds - disconnect first or Twisted throws a hissy fit
        logger.debug("Reboot key sequence complete, disconnecting and sleeping 45 seconds...")
        self.disconnect()
        time.sleep(45)
        logger.debug("Sleep finished, reconnecting and entering password")
        self.client = api.connect(self.address)
        # position for password box on 1650x1080 screen
        self.clickPos(797, 636)
        self.typestring(self.password)
        self.singleKey("enter")
        self.client.pause(self.randomTime(10))

    def prepVM(self, date, time):
        self.launchCMD()
        logger.debug("Preparing VM with date and time")
        self.typestring("date {0}".format(date))
        self.singleKey('enter')
        self.typestring("time {0}".format(time))
        self.singleKey('enter')
        self.typestring('exit')
        self.singleKey('enter')
        
    def basic(self):
        self.singleKey("lsuper")
        self.client.pause(self.randomTime(2))
        logger.debug("Launching Word")
        self.typestring("microsoft word")
        self.singleKey("enter")
        self.client.pause(self.randomTime(2))
        self.typestring("I've got a lovely bunch of coconuts")
        self.singleKey("enter")
        self.singleKey("enter")
        self.client.pause(self.randomTime(4))
        self.closeWindow()
        #self.mouseMove(127, 909)
        #self.mouseMove(1462, 932)
        self.randomMouseMove()
        self.randomMouseMove()
        self.client.pause(self.randomTime(8))
        #self.mouseMove(1137, 604)
        #self.mouseMove(479, 616)
        #self.mouseMove(473, 669)
        #self.mouseMove(617, 698)
        self.randomMouseMove()
        self.randomMouseMove()
        self.randomMouseMove()
        self.randomMouseMove()
        self.client.pause(self.randomTime(6))
        #self.mouseMove(33, 1036)
        self.randomMouseMove()
        
    def closeWindow(self):
        logger.debug("Closing window")
        self.client.keyDown("alt")
        self.client.keyPress("f4")
        self.client.keyUp("alt")
        self.client.pause(self.randomTime(2))
        self.singleKey("n")
        

    def disconnect(self):
        self.client.disconnect()

    def office_2007_enable_macros(self):
        logger.debug("Attempting to enable Office 2007 macros...")
        self.singleKey('alt')
        self.client.keyDown('ctrl')
        self.client.keyPress('tab')
        self.client.keyUp('ctrl')
        self.client.pause(0.2)
        self.singleKey('enter')
        self.client.pause(2)
        self.singleKey('e')
        self.singleKey('enter')
        
    def enable_macros(self, office_type):
        logger.debug("Finding office macro enable sequence...")
        if office_type == 1:
            self.office_2007_enable_macros()

#c = Connector("127.0.0.1::5900")

#c.prepVM('08/04/2017', '22:50:53')
#c.downloadAndRun('pafish.exe')
#c.closeWindow()
