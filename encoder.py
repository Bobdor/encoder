from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
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
import zlib
#from xml.sax.saxutils import unescape


# TODO:
	# Add more algorithms
	# Hex/String for input and output
	# Add the "send to" option
	# History

	

history = {}

historyIndex = 0

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IIntruderPayloadProcessor):

	

	def	registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Encoder")
		callbacks.registerContextMenuFactory(self)
		callbacks.registerIntruderPayloadProcessor(self)
		
		#Create Jpanel
		self._jPanel = swing.JPanel()
		self._jPanel.setLayout(None)
		self._jPanel.setPreferredSize(awt.Dimension(1200,1200))
		
		#Values for the combination boxes
		algOptions = ['Algorithm...', 'UTF-7', 'UTF-8', 'URL', 'Base64', 'XML', 'Binary', 'Overlong', 'zlib deflate']
		hashOptions = ['Hash...', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
		
		#GUI Components
		self.jEncode = swing.JRadioButton('Encode', actionPerformed=self.encodeButton)
		self.jDecode = swing.JRadioButton('Decode', actionPerformed=self.decodeButton)
		self.jAlgMenu = swing.JComboBox(algOptions)
		self.jInput = swing.JTextArea()
		self.jInputLabel = swing.JLabel()
		self.jOutput = swing.JTextArea()
		self.jInputScroll = swing.JScrollPane(self.jOutput)
		self.jOutputScroll = swing.JScrollPane(self.jOutput)
		self.jOutputLabel = swing.JLabel()
		self.jHashLabel = swing.JLabel()
		self.jHashMenu = swing.JComboBox(hashOptions)
		self.jStart = swing.JButton('Go', actionPerformed=self.doStart)
		self.jHex = swing.JRadioButton('Hex', actionPerformed=self.toHex)
		self.jString = swing.JRadioButton('String', actionPerformed=self.toString)
		self.jOutputFormat = swing.ButtonGroup()
		self.jSendToRequest = swing.JButton('Send to request', actionPerformed=self.sendToRequest)
		self.jToInput = swing.JButton('Send to Input', actionPerformed=self.toInput)
		self.jNextHistory = swing.JButton('>', actionPerformed=self.nextHistory)
		self.jPreviousHistory = swing.JButton('<', actionPerformed=self.previousHistory)
		
		
		#Input and Ouptut scroll
		self.jOutputScroll = swing.JScrollPane(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
		self.jOutputScroll.viewport.view = self.jOutput
		self.jInputScroll = swing.JScrollPane(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
		self.jInputScroll.viewport.view = self.jInput
		#Add buttons to group
		self.jOutputFormat.add(self.jString)
		self.jOutputFormat.add(self.jHex)


		
		#Configure GUIs
		
		self.jEncode.setSelected(True)
		self.jDecode.setSelected(False)
		self.jAlgMenu.setSelectedIndex(0)
		self.jInput.setLineWrap(True)
		self.jOutput.setLineWrap(True)
		self.jOutput.setEditable(False)
		self.jHashMenu.setSelectedIndex(0)
		self.jString.setSelected(True)
		
				
		#Component Locations
		
		self.jEncode.setBounds(15, 15, 70, 20)
		self.jDecode.setBounds(85, 15, 70, 20)
		self.jAlgMenu.setBounds(15, 45, 140, 25)
		self.jHashMenu.setBounds(15, 80, 140, 25)
		self.jStart.setBounds(15, 115, 140, 20)
		self.jSendToRequest.setBounds(15, 145, 140, 20)
		self.jHex.setBounds(15, 175, 70, 20)
		self.jString.setBounds(85, 175, 70, 20)
		self.jInputScroll.setBounds(165, 15, 800, 200)
		self.jOutputScroll.setBounds(165, 225, 800, 200)
		self.jToInput.setBounds(15, 405, 140, 20)
		self.jNextHistory.setBounds(85, 465, 70, 20)
		self.jPreviousHistory.setBounds(15, 465, 70, 20)
		
				
		#Add components to Panel
		self._jPanel.add(self.jEncode)
		self._jPanel.add(self.jDecode)
		self._jPanel.add(self.jAlgMenu)
		self._jPanel.add(self.jHashMenu)
		self._jPanel.add(self.jInputScroll)
		self._jPanel.add(self.jOutputScroll)
		self._jPanel.add(self.jStart)
		self._jPanel.add(self.jHex)
		self._jPanel.add(self.jString)
		self._jPanel.add(self.jSendToRequest)
		self._jPanel.add(self.jToInput)
		self._jPanel.add(self.jNextHistory)
		self._jPanel.add(self.jPreviousHistory)
		

		callbacks.customizeUiComponent(self._jPanel)
		callbacks.addSuiteTab(self)
		
		# set some values
		self._inputHex = False
		self._outputHex = False
		
		return
	# Intruder payload generator
	
	def getGeneratorName(self):
		return "Encoder"
		
	def createNewInstance(self, attack):
		return IntruderPayloadGenerator()
		
	def getProcessorName(self):
		return "Deflate"
		
	def processPayload(self, currentPayload, originalPayload, baseValue):
		print('test')
		return self.toZlib(currentPayload)
		
		
		
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
		global history
		global historyIndex
		# Get the parameters
		alg = self.jAlgMenu.getSelectedIndex()
		hashOption = self.jHashMenu.getSelectedIndex()
		if self.jEncode.isSelected() == True:
			direction = 0
		else:
			direction = 1
		
		# Encode/Decode without hashing		
		if hashOption == 0:
			if self.jDecode.isSelected():
				outputText = self.doDecode()
			elif self.jEncode.isSelected():
				outputText = self.doEncode()
			else: 
				outputText = 'did something wrong'
		
		# Encode/Decode and/or hash.
		elif hashOption != 0:
			if (self.jDecode.isSelected()):
				outputText = self.doHash(self.doDecode())
			elif (self.jEncode.isSelected()):
				outputText = self.doHash(self.doEncode())	
			else:
				outputText = self.doHash(self.jOutput.getText())
		else:
			outputText = 'did something wrong'
	
		#self.jAlgMenu.setSelectedIndex(0)
		self.jHashMenu.setSelectedIndex(0)
		#self.formatOutput()
		self.jOutput.setText(outputText)
		history[len(history)] = {"direction": direction, "alg": alg, "input": self.jInput.getText(), "output": outputText, "hash": hashOption}
		historyIndex = len(history) -1
		
		
	
# This part will encode the input. Will add more as needed
	def doEncode(self):
		try:
			message = self.jInput.getText()
		except:
			message = self.jInput.getText().encode('utf-16')
		toAlg = str(self.jAlgMenu.getSelectedItem())
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
		if toAlg == 'zlib deflate':
			return self.toZlib(message)
		
# This part will decode the input. Will add more as needed
	def doDecode(self):
		try:
			message = self.jInput.getText()
		except:
			message = self.jInput.getText().encode('utf-16')
		fromAlg = str(self.jAlgMenu.getSelectedItem())
		
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
		if fromAlg == 'zlib deflate':
			return self.fromZlib(message)
			
# Does the hashing part
# Want to find a way to use the variable to call the function
	def doHash(self, x):
		hashAlg = self.jHashMenu.getSelectedItem().encode('utf-16')
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
		if (self.jToMenu.getSelectedIndex() == 0) and (self.AlgMenu.getSelectedIndex() == 0) and (self.jHashMenu.getSelectedIndex() == 0):
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

		
		# Sends the output to the input
	def toInput(self, button):
		try:
			self.jInput.setText(self.jOutput.getText())
		except:
			self.jInput.setText(self.jOutput.getText().encode('utf-16', errors='ignore'))
		

	
	def previousHistory(self, button):
		global history
		global historyIndex
		if historyIndex > 0:
			historyIndex = historyIndex - 1
			if history[historyIndex]['direction'] == 0:
				self.jEncode.setSelected(True)
				self.jDecode.setSelected(False)
			elif history[historyIndex]['direction'] == 1:
				self.jEncode.setSelected(False)
				self.jDecode.setSelected(True)
			self.jHashMenu.setSelectedIndex(history[historyIndex]['hash'])
			self.jAlgMenu.setSelectedIndex(history[historyIndex]['alg'])
			self.jInput.setText(history[historyIndex]['input'])
			self.jOutput.setText(history[historyIndex]['output'])
				
		else:
			print('no more history')
		
	def nextHistory(self, button):
		global history
		global historyIndex
		if historyIndex < len(history) - 1:
			historyIndex = historyIndex + 1
			if history[historyIndex]['direction'] == 0:
				self.jEncode.setSelected(True)
				self.jDecode.setSelected(False)
			elif history[historyIndex]['direction'] == 1:
				self.jEncode.setSelected(False)
				self.jDecode.setSelected(True)
			self.jHashMenu.setSelectedIndex(history[historyIndex]['hash'])
			self.jAlgMenu.setSelectedIndex(history[historyIndex]['alg'])
			self.jInput.setText(history[historyIndex]['input'])
			self.jOutput.setText(history[historyIndex]['output'])
				
		else:
			print('newest')
	
	def encodeButton(self, button):
		self.jDecode.setSelected(False)
	
	def decodeButton(self, button):
		self.jEncode.setSelected(False)


	def toZlib(self, message):
		#message = self.jInput.getText()	
		messageOut = ""
		zlib_compress=zlib.compressobj(-1, zlib.DEFLATED, -15)
		messageOut = zlib_compress.compress(message)
		messageOut += zlib_compress.flush()
		return base64.b64encode(messageOut)
	 
	def fromZlib(self, message):
		#message = self.jInput.getText()
		return zlib.decompress(base64.b64decode(message), -8)
		
		
		
		
		
		
