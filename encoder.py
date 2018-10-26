from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IContextMenuFactory
#from burp import MenuItem
from java.awt import GridBagLayout
from java.awt import Font
from java.awt import Color
from java import awt
from java.awt import Component
from java.io import PrintWriter
from java.util import ArrayList
from java.util import List
from javax import swing
from threading import Lock
import hashlib
import base64
import binascii
import urllib
import re
import cgi
#from xml.sax.saxutils import unescape


# TODO:
	# Add more algorithms
	# Resize Boxes with frame size
	# Hex/String for input and output
	# Add the "send to" option


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):

	

	def	registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Encoder")
		callbacks.registerContextMenuFactory(self)
		
		#Create Jpanel
		self._jPanel = swing.JPanel()
		self._jPanel.setLayout(None)
		self._jPanel.setPreferredSize(awt.Dimension(1200,1200))
		
		#Values for the combination boxes
		fromOptions = ['Decode...', 'UTF-7', 'UTF-8', 'URL', 'Base64', 'XML', 'Binary', 'Overlong']
		toOptions = ['Encode...', 'UTF-7', 'UTF-8', 'URL', 'Base64', 'XML', 'Binary', 'Overlong']
		hashOptions = ['Hash...', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
		
		#GUI Components
		self.jFromMenu = swing.JComboBox(fromOptions)
		self.jToMenu = swing.JComboBox(toOptions)
		self.jInput = swing.JTextArea()
		self.jInputLabel = swing.JLabel()
		self.jOutput = swing.JTextArea()
		self.jOutputLabel = swing.JLabel()
		self.jHashLabel = swing.JLabel()
		self.jHashMenu = swing.JComboBox(hashOptions)
		self.jStart = swing.JButton('Go', actionPerformed=self.doStart)
		self.jHex = swing.JRadioButton('Hex', actionPerformed=self.toHex)
		self.jString = swing.JRadioButton('String', actionPerformed=self.toString)
		self.jOutputFormat = swing.ButtonGroup()
		self.jSendToRequest = swing.JButton('Send to request', actionPerformed=self.sendToRequest)
		
		#Add buttons to group
		self.jOutputFormat.add(self.jString)
		self.jOutputFormat.add(self.jHex)
		
		
		#Configure GUIs
		self.jFromMenu.setSelectedIndex(0)
		self.jToMenu.setSelectedIndex(0)
		self.jInput.setLineWrap(True)
		self.jOutput.setLineWrap(True)
		self.jOutput.setEditable(False)
		self.jHashMenu.setSelectedIndex(0)
		self.jString.setSelected(True)
				
		#Component Locations
		self.jFromMenu.setBounds(15, 15, 125, 20)
		self.jToMenu.setBounds(15, 45, 125, 20)
		self.jHashMenu.setBounds(15, 75, 125, 20)
		self.jStart.setBounds(15, 105, 125, 20)
		self.jSendToRequest.setBounds(15, 135, 125, 20)
		self.jHex.setBounds(15, 165, 55, 20)
		self.jString.setBounds(75, 165, 65, 20)
		self.jInput.setBounds(155, 15, 800, 200)
		self.jOutput.setBounds(155, 225, 800, 200)
				
		#Add components to Panel
		self._jPanel.add(self.jFromMenu)
		self._jPanel.add(self.jToMenu)
		self._jPanel.add(self.jHashMenu)
		self._jPanel.add(self.jInput)
		self._jPanel.add(self.jOutput)
		self._jPanel.add(self.jStart)
		self._jPanel.add(self.jHex)
		self._jPanel.add(self.jString)
		self._jPanel.add(self.jSendToRequest)

		callbacks.customizeUiComponent(self._jPanel)
		callbacks.addSuiteTab(self)
		
		# set some values
		self._inputHex = False
		self._outputHex = False
		
		return

	# implement ITab 
	def getTabCaption(self):
		return "Encoder"
	
	def getUiComponent(self):
		return self._jPanel
		
	# make menu item
	def createMenuItems(self,contextMenuInvocation):
		self.contextMenuData = contextMenuInvocation.getSelectedMessages()
		self.contextBounds = contextMenuInvocation.getSelectionBounds()
		self.ctx = contextMenuInvocation.getInvocationContext()
		menu_list = []
		menu_list.append(swing.JMenuItem("Encode...", actionPerformed=self.menuClicked))
		if (self.ctx == 2) or (self.ctx == 3):
			return menu_list
		if (self.ctx == 0):
			
			return menu_list
		
	def menuClicked(self, event):
		self.startIndex = self.contextBounds[0]
		self.endIndex = self.contextBounds[1]
		self.messageText = self.contextMenuData[0]
		reqInfo = self._helpers.analyzeRequest(self.messageText)
		self.reqBody = self.messageText.getRequest()
		self.respBody = self.messageText.getResponse()
		if (self.ctx == 0) or (self.ctx == 2):
			data = self._helpers.bytesToString(self.reqBody[self.startIndex:self.endIndex])
			#self.jInput.setText(str(data))
		elif self.ctx == 3:
			data = self._helpers.bytesToString(self.respBody[self.startIndex:self.endIndex])
		else:
			data = self.ctx
		self.jInput.setText(str(data))	
		self._jPanel.getParent().setSelectedComponent(self._jPanel)
	
	
	def doStart(self, button):
		self.start()
		
# Perform the requested functions
	def start(self):
		# Get the parameters
		toOption = self.jToMenu.getSelectedIndex()
		fromOption = self.jFromMenu.getSelectedIndex()
		hashOption = self.jHashMenu.getSelectedIndex()
		# Encode/Decode without hashing		
		if hashOption == 0:
			if (toOption == 0) and (fromOption != 0):
				self.jOutput.setText(self.doDecode())
			elif (fromOption == 0) and (toOption != 0):
				self.jOutput.setText(self.doEncode())
			else:
				self.jOutput.setText(self.jInput.getText())
		
		# Encode/Decode and/or hash.
		elif hashOption != 0:
			if (toOption == 0) and (fromOption != 0):
				self.jOutput.setText(self.doHash(self.doDecode()))
			elif (fromOption == 0) and (toOption != 0):
				self.jOutput.setText(self.doHash(self.doEncode()))	
			else:
				self.jOutput.setText(self.doHash(self.jOutput.getText()))
		else:
			self.jOutput.setText('did something wrong')
	
		self.jToMenu.setSelectedIndex(0)
		self.jFromMenu.setSelectedIndex(0)
		self.jHashMenu.setSelectedIndex(0)
		self.formatOutput()
	
# This part will encode the input. Will add more as needed
	def doEncode(self):
		message = str(self.jInput.getText())
		toAlg = str(self.jToMenu.getSelectedItem())
		if toAlg == 'Base64':
			return base64.b64encode(bytes(message),'utf-8').decode()
		if toAlg == 'URL':
			return urllib.quote_plus(message)
		if toAlg == 'UTF-7':
			return message.encode('utf7')
		if toAlg == 'UTF-8':
			return message.encode('utf8')
		if toAlg == 'XML':
			return cgi.escape(message, quote=True)
		if toAlg == 'Binary':
			return self.toBinary(message)
		if toAlg == 'Overlong':
			return self.toOverlong(message)
		
# This part will decode the input. Will add more as needed
	def doDecode(self):
		message = str(self.jInput.getText())
		fromAlg = str(self.jFromMenu.getSelectedItem())
		
		if (fromAlg == 'Plain') or (fromAlg == 'From...'):
			return message
		if fromAlg == 'Base64':
			return base64.b64decode(message)
		if fromAlg == 'URL':
			return urllib.unquote(message)
		if fromAlg == 'UTF-7':
			return message.decode(bytes(message, 'utf-7'), 'utf7')
		if fromAlg == 'UTF-8':
			return message.decode(bytes(message, 'utf-8'), 'utf8')
		if fromAlg == 'XML':
			return self.unescape(message)
		if fromAlg == 'Binary':
			return chr(int(message,2))
		if fromAlg == 'Overlong':
			return self.fromOverlong(message)
			
# Does the hashing part
# Want to find a way to use the variable to call the function
	def doHash(self, x):
		hashAlg = str(self.jHashMenu.getSelectedItem())
		if hashAlg == 'md5':
			return hashlib.md5(x).hexdigest()
		elif hashAlg == 'sha1':
			return hashlib.sha1(x).hexdigest()
		elif hashAlg == 'sha224':
			return hashlib.sha224(x).hexdigest()
		elif hashAlg == 'sha256':
			return hashlib.sha256(x).hexdigest()
		elif hashAlg == 'sha384':
			return hashlib.sha384(x).hexdigest()
		elif hashAlg == 'sha512':
			return hashlib.sha512(x).hexdigest()
		else:
			return 'error'

# Formats the output as string or hex based upon the buttons			
	def formatOutput(self):
		message = self.jOutput.getText()
		if self.jHex.isSelected():
			self.jOutput.setText(binascii.hexlify(message))
			self._outputHex = True
		elif self.jString.isSelected():
			self.jOutput.setText(binascii.unhexlify(message))
			self._outputHex = False
		else:
			self.jOutput.setText('something is wrong')
			
	def unescape(self, s):
		s = s.replace("&lt;", "<")
		s = s.replace("&gt;", ">")
		s = s.replace("&quot;", "\"")
		s = s.replace("&amp;", "&")
		return s


# Calls the format function and prevents unhexlify of hex			
	def toHex(self, button):
		if self._outputHex == False:
			self.formatOutput()
		else:
			return
	
	def toString(self, button):
		if self._outputHex == True:
			self.formatOutput()
		else:
			return
			
			
	def toOverlong(self, b):
		final = ''
		for x in b:
			y= ('110%s10%s' % (self.toBinary(x).zfill(11)[:5], self.toBinary(x).zfill(11)[5:]))
			final = final + ('%s%s%s%s' % ('%', hex(int(y,2))[2:4], '%', hex(int(y,2))[4:]))
		return final
	
	def fromOverlong(self, b):
		final = ''
		overlong = re.sub('%','',b)
		inc = 4
		while len(overlong) >= inc:
			chunk="{0:b}".format(int(overlong[inc-4:inc],16))
			char = chunk[7:9] + chunk[11:]
			final = final + chr(int(char,2))
			inc = inc + 4	
		return final
	
	def toBinary(self, a):
		return bin(int(binascii.hexlify(bytes(a)), 16))[2:]
			
	
	def sendToRequest(self, button):
		if (self.jToMenu.getSelectedIndex() == 0) and (self.jFromMenu.getSelectedIndex() == 0) and (self.jHashMenu.getSelectedIndex() == 0):
			output = self.jOutput.getText()
		else:
			return
		# else:
			# self.start()
			# output = self.jOutput.getText()
		orgMessage = self._helpers.bytesToString(self.reqBody)
		toRequestText = orgMessage[:self.startIndex] + output + orgMessage[self.endIndex:]
		self.messageText.setRequest(toRequestText)
		self._helpers.analyzeRequest(self.messageText)

		

