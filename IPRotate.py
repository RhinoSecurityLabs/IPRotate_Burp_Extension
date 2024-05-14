#AUTHOR: Dave Yesland @daveysec, Rhino Security Labs @rhinosecurity
#Burp Suite extension which uses AWS API Gateway to change your IP on every request to bypass IP blocking.
#More Info: https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/

from javax.swing import JPanel, JTextField, JButton, JLabel, BoxLayout, JPasswordField, JCheckBox, JRadioButton, ButtonGroup, Box
from burp import IBurpExtender, IExtensionStateListener, ITab, IHttpListener
from java.awt import GridLayout, Color
import os
import sys

# Include ./lib in the sys path so we can import boto3 from it
lib_path = os.path.abspath('./lib')
sys.path.append(lib_path)

try:
	import botocore.exceptions
	import boto3
	BOTO3_AVAILABLE=True
except Exception as e:
	BOTO3_AVAILABLE=False
	print('Unable to import boto3, create API Gateway manually using createapigw.py script, and load them from file.', e)

import re

EXT_NAME = 'IP Rotate'
ENABLED = 'ENABLED'
DISABLED = 'DISABLED'
STAGE_NAME = 'burpendpoint'
API_NAME = 'BurpAPI'
AVAIL_REGIONS = [
			"af-south-1",
			"ap-east-1",
			"ap-northeast-3",
			"eu-central-1",
			"eu-north-1",
			"eu-south-2",
			"sa-east-1",
			"us-east-1",
			"us-gov-east-1",
			"us-gov-west-1",
			"ap-northeast-1",
			"ap-northeast-2",
			"ap-southeast-2",
			"ap-southeast-3",
			"cn-northwest-1",
			"eu-south-1",
			"eu-west-1",
			"eu-west-2",
			"me-central-1",
			"us-east-2",
			"ap-south-2",
			"ap-southeast-1",
			"ap-southeast-4",
			"ca-central-1",
			"ca-west-1",
			"eu-central-2",
			"eu-west-3",
			"il-central-1",
			"us-west-1",
			"us-west-2",
			"ap-south-1",
			"cn-north-1",
			"me-south-1"
		]

class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IHttpListener):
	def __init__(self):
		self.allEndpoints = []
		self.currentEndpoint = 0
		self.aws_access_key_id = ''
		self.aws_secret_accesskey = ''
		self.enabled_regions = {}

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.helpers
		self.isEnabled = False

		callbacks.registerHttpListener(self)
		callbacks.registerExtensionStateListener(self)
		callbacks.setExtensionName(EXT_NAME)
		callbacks.addSuiteTab(self)


	def getTargetProtocol(self):
		if self.https_button.isSelected() == True:
			return 'https'
		else:
			return 'http'

	def getRegions(self):
		self.enabled_regions = {}
		for region in AVAIL_REGIONS:
			cur_region = region.replace('-','_')
			cur_region = cur_region+'_status'
			region_status = getattr(self,cur_region)
			if region_status.isSelected():
				#dict to contain the running regions and API gateway IDs
				self.enabled_regions.update({region:''})
		return


#AWS functions

	#Uses boto3 to test the AWS keys and make sure they are valid NOT IMPLEMENTED
	def testKeys(self):
		return
	
	def create_boto3_client(self, service_name, profile_name=None, access_key=None, secret_key=None, region=None):
		"""
		Creates a boto3 client for a given service.

		:param service_name: Name of the AWS service (e.g., 's3', 'ec2').
		:param profile_name: The name of the AWS profile to use.
		:param access_key: AWS access key ID.
		:param secret_key: AWS secret access key.
		:return: Boto3 client for the specified service.
		"""
		if profile_name:
			# Create a session using a specific profile
			session = boto3.Session(profile_name=profile_name)
			client = session.client(service_name, region_name=region)
		elif access_key and secret_key:
			# Create a client using access keys
			client = boto3.client(service_name, aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)

		return client

	#Uses boto3 to spin up an API Gateway
	def startAPIGateway(self):
		self.getRegions()
		for region in self.enabled_regions.keys():
			try:
				self.awsclient = self.create_boto3_client('apigateway',
					profile_name=self.aws_profile_name,
					access_key=self.aws_access_key_id,
					secret_key=self.aws_secret_access_key,
					region=region
				)

				self.create_api_response = self.awsclient.create_rest_api(
					name=API_NAME,
					endpointConfiguration={
						'types': [
							'REGIONAL',
						]
					}
				)
			except botocore.exceptions.ClientError:
				print "Starting API Gateway in "+region+" failed, skipping."
				cur_region = region.replace('-','_')
				cur_region = cur_region+'_status'
				region_status = getattr(self,cur_region)
				region_status.setSelected(False)
				del(self.enabled_regions[region])
				continue

			get_resource_response = self.awsclient.get_resources(
				restApiId=self.create_api_response['id']
			)
			
			self.restAPIId = self.create_api_response['id']
			self.enabled_regions[region] = self.restAPIId

			self.awsclient.create_resource(
				restApiId=self.create_api_response['id'],
				parentId=get_resource_response['items'][0]['id'],
				pathPart='{proxy+}'
			)
			
			self.awsclient.put_method(
				restApiId=self.create_api_response['id'],
				resourceId=get_resource_response['items'][0]['id'],
				httpMethod='ANY',
				authorizationType='NONE',
				requestParameters={
					'method.request.path.proxy':True,
					'method.request.header.X-My-X-Forwarded-For':True
                                }
			)

			self.awsclient.put_integration(
				restApiId=self.create_api_response['id'],
				resourceId=get_resource_response['items'][0]['id'],
				type='HTTP_PROXY',
				httpMethod='ANY',
				integrationHttpMethod='ANY',
				uri=self.getTargetProtocol()+'://'+self.target_host.text + '/',
				connectionType='INTERNET',
				requestParameters={
					'integration.request.path.proxy':'method.request.path.proxy',
                                        'integration.request.header.X-Forwarded-For': 'method.request.header.X-My-X-Forwarded-For'
				}
			)

			self.deploy_response = self.awsclient.create_deployment(
				restApiId=self.restAPIId,
				stageName=STAGE_NAME

			)

			self.allEndpoints.append(self.restAPIId+'.execute-api.'+region+'.amazonaws.com')
			
			self.usage_response = self.awsclient.create_usage_plan(
				name='burpusage',
				description=self.restAPIId,
				apiStages=[
					{
					'apiId': self.restAPIId,
					'stage': STAGE_NAME
					}
				]
			)

		#Print out some info to burp console
		print 'Following regions and API IDs started:'
		for enabled_region in self.enabled_regions:
			print enabled_region+":"+self.enabled_regions[enabled_region]
		print 'List of endpoints being used:'
		for endpoint in self.allEndpoints:
			print endpoint
		return

	#Uses boto3 to delete the API Gateway
	def deleteAPIGateway(self):
		if self.enabled_regions:
			for region in self.enabled_regions.keys():
				print "Deleting APIs in region: "+region
				try:
					self.awsclient = self.create_boto3_client('apigateway',
						profile_name=self.aws_profile_name,
						access_key=self.aws_access_key_id,
						secret_key=self.aws_secret_access_key,
						region=region
					)

					response = self.awsclient.delete_rest_api(
						restApiId=self.enabled_regions[region]
					)
					print "Deleted "+self.enabled_regions[region]+" From "+region
				except Exception as e:
					print e
					print "Failed to delete: "+self.enabled_regions[region]+" In "+region
					continue

		self.enabled_regions = {}
		self.allEndpoints = []
		return

	#Called on "save" button click to save the settings
	def saveKeys(self, event):
		aws_access_key_id=self.access_key.text
		aws_secret_access_key=self.secret_key.text
		self.callbacks.saveExtensionSetting("aws_access_key_id", aws_access_key_id)
		self.callbacks.saveExtensionSetting("aws_secret_access_key", aws_secret_access_key)
		return

	#Called on "Enable" button click to spin up the API Gateway
	def enableGateway(self, event):
		if BOTO3_AVAILABLE and not self.load_from_file.text:

			# Setup the credentials
			if self.profile_name.text:
				print "Using AWS Profile: "+self.profile_name.text
				self.aws_profile_name = self.profile_name.text
				self.aws_access_key_id = None
				self.aws_secret_access_key = None
			else:
				print "Using Access keys for AWS auth."
				self.aws_profile_name = None
				self.aws_access_key_id = self.access_key.text
				self.aws_secret_access_key = self.secret_key.text

			self.startAPIGateway()

			self.secret_key.setEnabled(False)
			self.access_key.setEnabled(False)
		elif len(self.allEndpoints) == 0:
			print('load API GW endpoints from file')
			return

		if self.allEndpoints:
			self.status_indicator.text = ENABLED
			self.status_indicator.setForeground(Color(0x00FF00))
			self.isEnabled = True
			self.enable_button.setEnabled(False)
			self.target_host.setEnabled(False)
			self.disable_button.setEnabled(True)
			return
		else:
			return

	#Called on "Disable" button click to delete API Gateway
	def disableGateway(self, event):
		if BOTO3_AVAILABLE and not self.load_from_file.text:
			self.deleteAPIGateway()
			self.secret_key.setEnabled(True)
			self.access_key.setEnabled(True)
		
		self.status_indicator.text = DISABLED
		self.status_indicator.setForeground(Color(0xFF0000))
		self.isEnabled = False
		self.enable_button.setEnabled(True)
		self.stage_name.setEnabled(True)
		self.target_host.setEnabled(True)
		self.disable_button.setEnabled(False)
		return

	def getCurrEndpoint(self):

		return 

	def loadFromFile(self, event):
		print('loading from file: '+self.load_from_file.text)
		self.allEndpoints = []

		with open(self.load_from_file.text, 'r') as f:
			
			for endpoint in f.readlines():
				endpoint = endpoint.strip()
				print('loading endpoint: ' + endpoint)

				self.allEndpoints.append(endpoint)
		print('loaded endpoints: {}'.format(len(self.allEndpoints)))
		self.status_indicator.text = 'loaded endpoints: {}'.format(len(self.allEndpoints))


	#Traffic redirecting
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		# only process requests
		if not messageIsRequest or not self.isEnabled:
			return

		# get the HTTP service for the request
		httpService = messageInfo.getHttpService()

		#Modify the request host, host header, and path to point to the new API endpoint
		#Should always use HTTPS because API Gateway only uses HTTPS
		if ':' in self.target_host.text: #hacky fix for https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension/issues/14
			host_no_port = self.target_host.text.split(':')[0]
			
		else:
			host_no_port = self.target_host.text

		if (host_no_port == httpService.getHost()):
			#Cycle through all the endpoints each request until then end of the list is reached
			if self.currentEndpoint < len(self.allEndpoints)-1:
				self.currentEndpoint += 1
			#Reset to 0 when end it reached
			else:
				self.currentEndpoint = 0

			messageInfo.setHttpService(
				self.helpers.buildHttpService(
					self.allEndpoints[self.currentEndpoint],
					443, True
				)
			)

			requestInfo = self.helpers.analyzeRequest(messageInfo)
			new_headers = requestInfo.headers

			#Update the path to point to the API Gateway path
			req_head = new_headers[0]
			#hacky fix for https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension/issues/14
			if 'http://' in req_head or 'https://' in req_head:
				cur_path = re.findall('https?:\/\/.*?\/(.*) ',req_head)[0]
				new_headers[0] = re.sub(' (.*?) '," /"+self.stage_name.text+"/"+cur_path+" ",req_head)

			else:
				new_headers[0] = re.sub(' \/'," /"+self.stage_name.text+"/",req_head)

			#Replace the Host header with the Gateway host
			for header in new_headers:
				if header.startswith('Host: '):
					host_header_index = new_headers.index(header)
					new_headers[host_header_index] = 'Host: ' + messageInfo.getHttpService().getHost()

			#Update the headers insert the existing body
			body = messageInfo.request[requestInfo.getBodyOffset():len(messageInfo.request)]
			messageInfo.request = self.helpers.buildHttpMessage(
								new_headers,
								body
							)

	#Tab name
	def getTabCaption(self):
		return EXT_NAME

	#Handle extension unloading
	def extensionUnloaded(self):
		self.deleteAPIGateway()
		return
	
	# Select all regions
	def selectAllRegions(self, event):
		for region in AVAIL_REGIONS:
			cur_region = region.replace('-','_')
			cur_region = cur_region+'_status'
			region_status = getattr(self,cur_region)
			region_status.setSelected(False)
		
	# Deselect all regions
	def deselectAllRegions(self, event):
		for region in AVAIL_REGIONS:
			cur_region = region.replace('-','_')
			cur_region = cur_region+'_status'
			region_status = getattr(self,cur_region)
			region_status.setSelected(True)

	#Layout the UI
	def getUiComponent(self):
		aws_access_key_id = self.callbacks.loadExtensionSetting("aws_access_key_id")
		aws_secret_accesskey = self.callbacks.loadExtensionSetting("aws_secret_access_key")
		load_from_file = self.callbacks.loadExtensionSetting("load_from_file")
		stage_name = self.callbacks.loadExtensionSetting("stage_name")
		if aws_access_key_id:
			self.aws_access_key_id = aws_access_key_id
		if aws_secret_accesskey:
			self.aws_secret_accesskey = aws_secret_accesskey
		if not stage_name:
			stage_name = STAGE_NAME
		if not aws_secret_accesskey:
			load_from_file = ''

		self.panel = JPanel()

		self.main = JPanel()
		self.main.setLayout(BoxLayout(self.main, BoxLayout.Y_AXIS))

		self.profile_name_panel = JPanel()
		self.main.add(self.profile_name_panel)
		self.profile_name_panel.setLayout(BoxLayout(self.profile_name_panel, BoxLayout.X_AXIS))
		self.profile_name_panel.add(JLabel('AWS Profile Name: '))
		self.profile_name = JTextField("",25)
		self.profile_name_panel.add(self.profile_name)
		self.profile_name.setEnabled(BOTO3_AVAILABLE)

		# Adding space between the panels
		verticalStrut = Box.createVerticalStrut(10)  # Adjust 10 to increase/decrease spacing
		self.main.add(verticalStrut)
		
		self.optional_label = JPanel()
		self.main.add(self.optional_label)
		self.optional_label.add(JLabel('Or'))

		self.access_key_panel = JPanel()
		self.main.add(self.access_key_panel)
		self.access_key_panel.setLayout(BoxLayout(self.access_key_panel, BoxLayout.X_AXIS))
		self.access_key_panel.add(JLabel('Access Key: '))
		self.access_key = JTextField(self.aws_access_key_id,25)
		self.access_key_panel.add(self.access_key)
		self.access_key.setEnabled(BOTO3_AVAILABLE)

		self.secret_key_panel = JPanel()
		self.main.add(self.secret_key_panel)
		self.secret_key_panel.setLayout(BoxLayout(self.secret_key_panel, BoxLayout.X_AXIS))
		self.secret_key_panel.add(JLabel('Secret Key: '))
		self.secret_key = JPasswordField(self.aws_secret_accesskey,25)
		self.secret_key_panel.add(self.secret_key)
		self.secret_key.setEnabled(BOTO3_AVAILABLE)

		# Adding space between the panels
		verticalStrut = Box.createVerticalStrut(10)  # Adjust 10 to increase/decrease spacing
		self.main.add(verticalStrut)
		
		self.stage_name_panel = JPanel()
		self.main.add(self.stage_name_panel)
		self.stage_name_panel.setLayout(BoxLayout(self.stage_name_panel, BoxLayout.X_AXIS))
		self.stage_name_panel.add(JLabel('Stage name: '))
		self.stage_name = JTextField(stage_name,25)
		self.stage_name_panel.add(self.stage_name)

		self.target_host_panel = JPanel()
		self.main.add(self.target_host_panel)
		self.target_host_panel.setLayout(BoxLayout(self.target_host_panel, BoxLayout.X_AXIS))
		self.target_host_panel.add(JLabel('Target host: '))
		self.target_host = JTextField('ipinfo.io', 25)
		self.target_host_panel.add(self.target_host)

		self.buttons_panel = JPanel()
		self.main.add(self.buttons_panel)
		self.buttons_panel.setLayout(BoxLayout(self.buttons_panel, BoxLayout.X_AXIS))
		self.save_button = JButton('Save Keys', actionPerformed = self.saveKeys)
		self.buttons_panel.add(self.save_button)
		self.save_button.setEnabled(BOTO3_AVAILABLE)
		self.enable_button = JButton('Enable', actionPerformed = self.enableGateway)
		self.buttons_panel.add(self.enable_button)
		self.disable_button = JButton('Disable', actionPerformed = self.disableGateway)
		self.buttons_panel.add(self.disable_button)
		self.disable_button.setEnabled(False)

		self.protocol_panel = JPanel()
		self.main.add(self.protocol_panel)
		self.protocol_panel.setLayout(BoxLayout(self.protocol_panel, BoxLayout.Y_AXIS))
		self.protocol_panel.add(JLabel("Target Protocol:"))
		self.https_button = JRadioButton("HTTPS",True)
		self.http_button = JRadioButton("HTTP",False)
		self.protocol_panel.add(self.http_button)
		self.protocol_panel.add(self.https_button)
		buttongroup = ButtonGroup()
		buttongroup.add(self.https_button)
		buttongroup.add(self.http_button)

		# Adding space between the panels
		verticalStrut = Box.createVerticalStrut(10)  # Adjust 10 to increase/decrease spacing
		self.main.add(verticalStrut)
		
		self.optional_label = JPanel()
		self.main.add(self.optional_label)
		self.optional_label.add(JLabel('Optional/Advanced'))

		self.load_from_file_panel = JPanel()
		self.main.add(self.load_from_file_panel)
		self.load_from_file_panel.setLayout(BoxLayout(self.load_from_file_panel, BoxLayout.X_AXIS))
		self.load_from_file_panel.add(JLabel('API GW file: '))
		self.load_from_file = JTextField(load_from_file,25)
		self.load_from_file_panel.add(self.load_from_file)

		self.load_from_file_panel = JPanel()
		self.main.add(self.load_from_file_panel)
		self.load_from_file_button = JButton('Load from file', actionPerformed = self.loadFromFile)
		self.load_from_file_panel.add(self.load_from_file_button)

		self.regions_title = JPanel()
		self.main.add(self.regions_title)
		self.regions_title.add(JLabel("Regions to launch API Gateways in (Any failed regions will be skipped):"))

		self.buttons_panel2 = JPanel()
		self.main.add(self.buttons_panel2)
		self.buttons_panel2.setLayout(BoxLayout(self.buttons_panel2, BoxLayout.X_AXIS))
		self.save_button = JButton('Select All', actionPerformed = self.deselectAllRegions)
		self.buttons_panel2.add(self.save_button)
		self.enable_button = JButton('Deselect All', actionPerformed = self.selectAllRegions)
		self.buttons_panel2.add(self.enable_button)

		self.regions_panel = JPanel()
		self.main.add(self.regions_panel)
		glayout = GridLayout(4,3)
		self.regions_panel.setLayout(glayout)
		for region in AVAIL_REGIONS:
			cur_region = region.replace('-','_')
			cur_region = cur_region+'_status'
			setattr(self,cur_region,JCheckBox(region,True))
			attr = getattr(self,cur_region)
			self.regions_panel.add(attr)

		self.status = JPanel()
		self.main.add(self.status)
		self.status.setLayout(BoxLayout(self.status, BoxLayout.X_AXIS))
		self.status_indicator = JLabel(DISABLED,JLabel.CENTER)
		self.status_indicator.setForeground(Color(0xFF0000))
		self.status.add(self.status_indicator)
		
		self.panel.add(self.main)
		print "UI loaded"
		return self.panel

