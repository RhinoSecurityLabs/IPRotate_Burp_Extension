#AUTHOR: Dave Yesland @daveysec, Rhino Security Labs @rhinosecurity
#Burp Suite extension which uses AWS API Gateway to change your IP on every request to bypass IP blocking.
#More Info: https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/

from javax.swing import JPanel, JTextField, JButton, JLabel, BoxLayout, JPasswordField, JCheckBox, JRadioButton, ButtonGroup
from burp import IBurpExtender, IExtensionStateListener, ITab, IHttpListener
from java.awt import GridLayout
import boto3
import re

EXT_NAME = 'IP Rotate'
ENABLED = '<html><h2><font color="green">Enabled</font></h2></html>'
DISABLED = '<html><h2><font color="red">Disabled</font></h2></html>'
STAGE_NAME = 'burpendpoint'
API_NAME = 'BurpAPI'
AVAIL_REGIONS = [
	"us-east-1","us-west-1","us-east-2",
	"us-west-2","eu-central-1","eu-west-1",
	"eu-west-2","eu-west-3","sa-east-1","eu-north-1"
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

	#Uses boto3 to spin up an API Gateway
	def startAPIGateway(self):
		self.getRegions()
		for region in self.enabled_regions.keys():
			self.awsclient = boto3.client('apigateway',
				aws_access_key_id=self.access_key.text,
				aws_secret_access_key=self.secret_key.text,
				region_name=region
			)

			self.create_api_response = self.awsclient.create_rest_api(
				name=API_NAME,
				endpointConfiguration={
					'types': [
						'REGIONAL',
					]
				}
			)

			get_resource_response = self.awsclient.get_resources(
				restApiId=self.create_api_response['id']
			)
			
			self.restAPIId = self.create_api_response['id']
			self.enabled_regions[region] = self.restAPIId

			create_resource_response = self.awsclient.create_resource(
				restApiId=self.create_api_response['id'],
				parentId=get_resource_response['items'][0]['id'],
				pathPart='{proxy+}'
			)
			
			self.awsclient.put_method(
				restApiId=self.create_api_response['id'],
				resourceId=get_resource_response['items'][0]['id'],
				httpMethod='ANY',
				authorizationType='NONE'
			)

			self.awsclient.put_integration(
				restApiId=self.create_api_response['id'],
				resourceId=get_resource_response['items'][0]['id'],
				type='HTTP_PROXY',
				httpMethod='ANY',
				integrationHttpMethod='ANY',
				uri=self.getTargetProtocol()+'://'+self.target_host.text + '/',
				connectionType='INTERNET'
			)

			self.awsclient.put_method(
				restApiId=self.create_api_response['id'],
				resourceId=create_resource_response['id'],
				httpMethod='ANY',
				authorizationType='NONE',
				requestParameters={
					'method.request.path.proxy':True
				}
			)

			self.awsclient.put_integration(
				restApiId=self.create_api_response['id'],
				resourceId=create_resource_response['id'],
				type= 'HTTP_PROXY', 
				httpMethod= 'ANY',
				integrationHttpMethod='ANY',
				uri= self.getTargetProtocol()+'://'+self.target_host.text+'/{proxy}',
				connectionType= 'INTERNET',
				requestParameters={
					'integration.request.path.proxy':'method.request.path.proxy'
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
		print self.enabled_regions
		print 'List of endpoints being used:'
		print self.allEndpoints
		return

	#Uses boto3 to delete the API Gateway
	def deleteAPIGateway(self):
		if self.enabled_regions:
			for region in self.enabled_regions.keys():
				self.awsclient = boto3.client('apigateway',
					aws_access_key_id=self.access_key.text,
					aws_secret_access_key=self.secret_key.text,
					region_name=region
				)

				response = self.awsclient.delete_rest_api(
					restApiId=self.enabled_regions[region]
				)
				print response
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
		self.startAPIGateway()
		self.status_indicator.text = ENABLED
		self.isEnabled = True
		self.enable_button.setEnabled(False)
		self.secret_key.setEnabled(False)
		self.access_key.setEnabled(False)
		self.target_host.setEnabled(False)
		self.disable_button.setEnabled(True)
		return

	#Called on "Disable" button click to delete API Gateway
	def disableGateway(self, event):
		self.deleteAPIGateway()
		self.status_indicator.text = DISABLED
		self.isEnabled = False
		self.enable_button.setEnabled(True)
		self.secret_key.setEnabled(True)
		self.access_key.setEnabled(True)
		self.target_host.setEnabled(True)
		self.disable_button.setEnabled(False)
		return

	def getCurrEndpoint():

		return 

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
				new_headers[0] = re.sub(' (.*?) '," /"+STAGE_NAME+"/"+cur_path+" ",req_head)

			else:
				new_headers[0] = re.sub(' \/'," /"+STAGE_NAME+"/",req_head)

			#Replace the Host header with the Gateway host
			for header in new_headers:
				if header.startswith('Host: '):
					host_header_index = new_headers.index(header)
					new_headers[host_header_index] = 'Host: '+self.allEndpoints[self.currentEndpoint]

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

	#Layout the UI
	def getUiComponent(self):
		aws_access_key_id = self.callbacks.loadExtensionSetting("aws_access_key_id")
		aws_secret_accesskey = self.callbacks.loadExtensionSetting("aws_secret_access_key")
		if aws_access_key_id:
			self.aws_access_key_id = aws_access_key_id
		if aws_secret_accesskey:
			self.aws_secret_accesskey = aws_secret_accesskey

		self.panel = JPanel()

		self.main = JPanel()
		self.main.setLayout(BoxLayout(self.main, BoxLayout.Y_AXIS))

		self.access_key_panel = JPanel()
		self.main.add(self.access_key_panel)
		self.access_key_panel.setLayout(BoxLayout(self.access_key_panel, BoxLayout.X_AXIS))
		self.access_key_panel.add(JLabel('Access Key: '))
		self.access_key = JTextField(self.aws_access_key_id,25)
		self.access_key_panel.add(self.access_key)

		self.secret_key_panel = JPanel()
		self.main.add(self.secret_key_panel)
		self.secret_key_panel.setLayout(BoxLayout(self.secret_key_panel, BoxLayout.X_AXIS))
		self.secret_key_panel.add(JLabel('Secret Key: '))
		self.secret_key = JPasswordField(self.aws_secret_accesskey,25)
		self.secret_key_panel.add(self.secret_key)

		self.target_host_panel = JPanel()
		self.main.add(self.target_host_panel)
		self.target_host_panel.setLayout(BoxLayout(self.target_host_panel, BoxLayout.X_AXIS))
		self.target_host_panel.add(JLabel('Target host: '))
		self.target_host = JTextField('example.com', 25)
		self.target_host_panel.add(self.target_host)

		self.buttons_panel = JPanel()
		self.main.add(self.buttons_panel)
		self.buttons_panel.setLayout(BoxLayout(self.buttons_panel, BoxLayout.X_AXIS))
		self.save_button = JButton('Save Keys', actionPerformed = self.saveKeys)
		self.buttons_panel.add(self.save_button)
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

		self.regions_title = JPanel()
		self.main.add(self.regions_title)
		self.regions_title.add(JLabel("Regions to launch API Gateways in:"))

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
		self.status.add(self.status_indicator)
		
		self.panel.add(self.main)
		return self.panel
